from typing import Dict, Any, List, TypedDict
from langgraph.graph import StateGraph, END
from langchain.messages import HumanMessage, SystemMessage
from langchain_deepseek import ChatDeepSeek
import config
from .tool_agents import ToolAgents
import json

class AgentState(TypedDict):
    """智能体状态定义"""
    email_data: Dict[str, Any]
    header_result: Dict[str, Any]
    content_result: Dict[str, Any]
    url_result: Dict[str, Any]
    attachment_result: Dict[str, Any]
    final_decision: Dict[str, Any]
    analysis_chain: List[str]
    need_human_review: bool

class CentralControlAgent:
    def __init__(self):
        """初始化中央控制智能体"""
        self.llm = ChatDeepSeek(
            model="deepseek-chat",
            temperature=config.config.AGENT_TEMPERATURE,
            api_key=config.config.DEEPSEEK_API_KEY,
            base_url=config.config.DEEPSEEK_API_BASE
        )
        
        self.tool_agents = ToolAgents()
        self.graph = self._create_workflow()
    
    def _create_workflow(self):
        """创建智能体协同工作流"""
        workflow = StateGraph(AgentState)
        
        # 添加节点
        workflow.add_node("header_analysis", self._header_analysis_node)
        workflow.add_node("content_analysis", self._content_analysis_node)
        workflow.add_node("url_analysis", self._url_analysis_node)
        workflow.add_node("attachment_analysis", self._attachment_analysis_node)
        workflow.add_node("final_decision", self._final_decision_node)
        workflow.add_node("human_review", self._human_review_node)
        
        # 设置入口点
        workflow.set_entry_point("header_analysis")
        
        # 定义工作流路径
        workflow.add_edge("header_analysis", "content_analysis")
        workflow.add_edge("content_analysis", "url_analysis")
        workflow.add_edge("url_analysis", "attachment_analysis")
        workflow.add_edge("attachment_analysis", "final_decision")
        
        # 条件边：是否需要人工审核
        workflow.add_conditional_edges(
            "final_decision",
            self._should_require_human_review,
            {
                "human_review": "human_review",
                "end": END
            }
        )
        
        workflow.add_edge("human_review", END)
        
        return workflow.compile()
    
    def _header_analysis_node(self, state: AgentState) -> AgentState:
        """邮件头分析节点"""
        print("🔍 正在分析邮件头...")
        
        email_data = state["email_data"]
        headers = email_data.get("headers", {})
        
        # 调用头部检测智能体
        result = self.tool_agents.header_detection_agent(headers)
        
        state["header_result"] = result
        state["analysis_chain"].append("header_analysis")
        
        print(f"✅ 邮件头分析完成 - 风险等级: {result.get('risk_level', 'unknown')}")
        return state
    
    def _content_analysis_node(self, state: AgentState) -> AgentState:
        """内容语义分析节点"""
        print("📝 正在分析邮件内容...")
        
        email_data = state["email_data"]
        content = email_data.get("body", "")
        subject = email_data.get("subject", "")
        
        # 调用内容检测智能体
        result = self.tool_agents.content_semantic_agent(content, subject)
        
        state["content_result"] = result
        state["analysis_chain"].append("content_analysis")
        
        print(f"✅ 内容分析完成 - 风险等级: {result.get('risk_level', 'unknown')}")
        return state
    
    def _url_analysis_node(self, state: AgentState) -> AgentState:
        """URL分析节点"""
        print("🔗 正在分析URL...")
        
        email_data = state["email_data"]
        urls = email_data.get("urls", [])
        
        # 调用URL检测智能体
        result = self.tool_agents.url_detection_agent(urls)
        
        state["url_result"] = result
        state["analysis_chain"].append("url_analysis")
        
        print(f"✅ URL分析完成 - 风险等级: {result.get('risk_level', 'unknown')}")
        return state
    
    def _attachment_analysis_node(self, state: AgentState) -> AgentState:
        """附件分析节点"""
        print("📎 正在分析附件...")
        
        email_data = state["email_data"]
        attachments = email_data.get("attachments", [])
        
        # 调用附件检测智能体
        result = self.tool_agents.attachment_detection_agent(attachments)
        
        state["attachment_result"] = result
        state["analysis_chain"].append("attachment_analysis")
        
        print(f"✅ 附件分析完成 - 风险等级: {result.get('risk_level', 'unknown')}")
        return state
    
    def _final_decision_node(self, state: AgentState) -> AgentState:
        """最终决策节点"""
        print("🤖 正在生成最终决策...")
        
        # 收集所有检测结果
        results = {
            "header": state.get("header_result", {}),
            "content": state.get("content_result", {}),
            "url": state.get("url_result", {}),
            "attachment": state.get("attachment_result", {})
        }
        
        # 调用LLM进行综合评估
        decision = self._make_final_decision(results)
        
        state["final_decision"] = decision
        state["analysis_chain"].append("final_decision")
        
        print(f"✅ 最终决策完成 - 恶意邮件: {decision.get('is_malicious', False)}")
        return state
    
    def _make_final_decision(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """基于所有检测结果做出最终决策"""
        try:
            prompt = SystemMessage(content="""
            你是一个恶意邮件检测专家。请基于以下各智能体的检测结果，做出综合判断。
            
            输出格式必须为JSON，包含以下字段：
            - is_malicious: bool (是否为恶意邮件)
            - confidence: float (总体置信度 0-1)
            - risk_level: str (总体风险等级: low/medium/high/critical)
            - malicious_components: list (哪些部分被检测为恶意)
            - threat_type: str (威胁类型: phishing/malware/spam/benign)
            - recommendations: list (建议措施)
            - summary: str (简要总结)
            """)
            
            human_msg = HumanMessage(content=f"""
            请综合分析以下检测结果：
            
            1. 邮件头检测结果:
            {json.dumps(results.get('header', {}), indent=2, ensure_ascii=False)}
            
            2. 内容语义检测结果:
            {json.dumps(results.get('content', {}), indent=2, ensure_ascii=False)}
            
            3. URL检测结果:
            {json.dumps(results.get('url', {}), indent=2, ensure_ascii=False)}
            
            4. 附件检测结果:
            {json.dumps(results.get('attachment', {}), indent=2, ensure_ascii=False)}
            
            请给出最终判断。
            """)
            
            response = self.llm.invoke([prompt, human_msg])
            
            # 解析响应
            import re
            json_match = re.search(r'\{.*\}', response.content, re.DOTALL)
            if json_match:
                decision = json.loads(json_match.group())
            else:
                decision = self._calculate_decision_by_rules(results)
            
            return decision
            
        except Exception as e:
            return self._calculate_decision_by_rules(results)
    
    def _calculate_decision_by_rules(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """基于规则的决策计算（备用）"""
        malicious_count = 0
        high_risk_count = 0
        malicious_components = []
        
        for agent_name, result in results.items():
            if result.get("is_malicious", False):
                malicious_count += 1
                malicious_components.append(agent_name)
            
            if result.get("risk_level") in ["high", "critical"]:
                high_risk_count += 1
        
        # 决策逻辑
        if high_risk_count >= 2 or malicious_count >= 3:
            is_malicious = True
            risk_level = "critical"
            confidence = 0.9
        elif malicious_count >= 2:
            is_malicious = True
            risk_level = "high"
            confidence = 0.7
        elif malicious_count >= 1:
            is_malicious = True
            risk_level = "medium"
            confidence = 0.6
        else:
            is_malicious = False
            risk_level = "low"
            confidence = 0.9
        
        return {
            "is_malicious": is_malicious,
            "confidence": confidence,
            "risk_level": risk_level,
            "malicious_components": malicious_components,
            "threat_type": "phishing" if is_malicious else "benign",
            "recommendations": ["隔离邮件", "不要点击链接"] if is_malicious else ["正常邮件"],
            "summary": f"检测到{malicious_count}个恶意组件，{high_risk_count}个高风险组件"
        }
    
    def _should_require_human_review(self, state: AgentState) -> str:
        """判断是否需要人工审核"""
        decision = state.get("final_decision", {})
        
        # 条件：高风险但置信度不高，需要人工审核
        if decision.get("risk_level") in ["high", "critical"]:
            confidence = decision.get("confidence", 0)
            if confidence < config.config.DETECTION_THRESHOLD:
                state["need_human_review"] = True
                return "human_review"
        
        state["need_human_review"] = False
        return "end"
    
    def _human_review_node(self, state: AgentState) -> AgentState:
        """人工审核节点"""
        print("👤 需要人工审核...")
        
        decision = state.get("final_decision", {})
        decision["needs_human_review"] = True
        decision["automated_decision"] = decision.get("is_malicious", False)
        decision["final_decision_pending"] = True
        
        state["final_decision"] = decision
        
        print("📋 邮件已标记为需要人工审核")
        return state
    
    def analyze_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析邮件"""
        print("🚀 开始恶意邮件检测分析...")
        
        # 初始化状态
        initial_state: AgentState = {
            "email_data": email_data,
            "header_result": {},
            "content_result": {},
            "url_result": {},
            "attachment_result": {},
            "final_decision": {},
            "analysis_chain": [],
            "need_human_review": False
        }
        
        # 执行工作流
        final_state = self.graph.invoke(initial_state)
        
        # 整理结果
        result = {
            "final_decision": final_state["final_decision"],
            "component_results": {
                "header": final_state["header_result"],
                "content": final_state["content_result"],
                "url": final_state["url_result"],
                "attachment": final_state["attachment_result"]
            },
            "analysis_chain": final_state["analysis_chain"],
            "need_human_review": final_state.get("need_human_review", False)
        }
        
        print("🎉 分析完成!")
        return result