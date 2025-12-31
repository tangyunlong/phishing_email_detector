from typing import Dict, Any, Optional
# from langchain.tools import tool
from langchain_deepseek import ChatDeepSeek
from langchain_core.prompts import PromptTemplate
from langchain_core.tools import Tool
import config
import re
import json

class ToolAgents:
    def __init__(self):
        """初始化所有工具智能体"""
        self.llm = ChatDeepSeek(
            model="deepseek-chat",
            temperature=config.config.AGENT_TEMPERATURE,
            api_key=config.config.DEEPSEEK_API_KEY,
            base_url=config.config.DEEPSEEK_API_BASE
        )
        
    def header_detection_agent(self, email_headers: Dict[str, Any]) -> Dict[str, Any]:
        """
        邮件头检测智能体
        检测可疑的邮件头信息
        """
        try:
            # 构建检测提示
            prompt = PromptTemplate.from_template("""
            请分析以下邮件头信息，判断是否存在恶意特征：
            
            邮件头信息：
            {headers}
            
            请检查以下内容：
            1. SPF、DKIM、DMARC验证状态
            2. 发件人地址是否可疑
            3. 邮件路由是否异常
            4. 是否有伪造的头部信息
            
            请以JSON格式返回分析结果，包含以下字段：
            - is_malicious: bool (是否为恶意)
            - confidence: float (置信度 0-1)
            - suspicious_indicators: list (可疑指标列表)
            - risk_level: str (风险等级: low/medium/high)
            - details: str (详细分析)
            """)
            
            # 格式化为字符串
            headers_str = json.dumps(email_headers, indent=2, ensure_ascii=False)
            
            # 调用LLM
            chain = prompt | self.llm
            response = chain.invoke({"headers": headers_str})
            
            # 解析响应
            result = self._parse_llm_response(response.content)
            
            # 添加一些规则检测
            result = self._enhance_header_detection(email_headers, result)
            
            return result
            
        except Exception as e:
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "suspicious_indicators": [f"检测错误: {str(e)}"],
                "risk_level": "low",
                "details": f"头部检测时发生错误: {str(e)}"
            }
    
    def content_semantic_agent(self, email_content: str, subject: str = "") -> Dict[str, Any]:
        """
        内容语义检测智能体
        分析邮件内容的语义特征
        """
        try:
            prompt = PromptTemplate.from_template("""
            请分析以下邮件内容，判断是否存在恶意意图或钓鱼特征：
            
            邮件主题: {subject}
            邮件内容: {content}
            
            请检查以下特征：
            1. 紧急或威胁性语言
            2. 索要敏感信息的请求
            3. 语法错误或不自然的表达
            4. 冒充知名机构或联系人
            5. 异常的情绪诱导
            
            请以JSON格式返回分析结果，包含以下字段：
            - is_malicious: bool
            - confidence: float (0-1)
            - suspicious_phrases: list (可疑短语列表)
            - phishing_indicators: list (钓鱼指标)
            - risk_level: str (low/medium/high)
            - details: str
            """)
            
            chain = prompt | self.llm
            response = chain.invoke({
                "subject": subject,
                "content": email_content[:2000]  # 限制长度
            })
            
            result = self._parse_llm_response(response.content)
            
            # 增强检测
            result = self._enhance_content_detection(email_content, subject, result)
            
            return result
            
        except Exception as e:
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "suspicious_phrases": [],
                "phishing_indicators": [f"检测错误: {str(e)}"],
                "risk_level": "low",
                "details": f"内容检测时发生错误: {str(e)}"
            }
    
    def url_detection_agent(self, urls: list) -> Dict[str, Any]:
        """
        URL检测智能体
        检测邮件中的可疑URL
        """
        try:
            # 简化的URL检测逻辑（后续可扩展）
            suspicious_urls = []
            risk_level = "low"
            
            for url in urls:
                # 基础检测规则
                if self._is_suspicious_url(url):
                    suspicious_urls.append({
                        "url": url,
                        "reason": self._get_url_suspicion_reason(url)
                    })
            
            # 调用LLM进行语义分析
            if urls:
                prompt = PromptTemplate.from_template("""
                分析以下URL列表，判断是否存在钓鱼或恶意链接风险：
                
                URL列表:
                {urls}
                
                请以JSON格式返回分析结果，包含：
                - is_malicious: bool
                - confidence: float
                - malicious_urls: list
                - risk_level: str
                - details: str
                """)
                
                chain = prompt | self.llm
                response = chain.invoke({"urls": json.dumps(urls)})
                
                llm_result = self._parse_llm_response(response.content)
                
                # 合并规则和LLM结果
                if suspicious_urls:
                    llm_result["suspicious_urls"] = suspicious_urls
                    if llm_result["risk_level"] == "low":
                        llm_result["risk_level"] = "medium"
                
                return llm_result
            
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "malicious_urls": [],
                "risk_level": "low",
                "details": "未发现URL"
            }
            
        except Exception as e:
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "malicious_urls": [],
                "risk_level": "low",
                "details": f"URL检测错误: {str(e)}"
            }
    
    def attachment_detection_agent(self, attachments: list) -> Dict[str, Any]:
        """
        附件检测智能体
        检测可疑附件
        """
        try:
            # 简化的附件检测（后续可扩展）
            suspicious_attachments = []
            
            for attachment in attachments:
                # 基础检测规则
                if self._is_suspicious_attachment(attachment):
                    suspicious_attachments.append({
                        "filename": attachment.get("filename", ""),
                        "filetype": attachment.get("filetype", ""),
                        "reason": "可疑文件类型"
                    })
            
            # 如果有附件，调用LLM分析
            if attachments:
                prompt = PromptTemplate.from_template("""
                分析以下邮件附件信息，判断是否存在恶意文件风险：
                
                附件列表:
                {attachments}
                
                请考虑以下因素：
                1. 文件类型风险（如.exe, .js等可执行文件）
                2. 文件名可疑性
                3. 文件大小异常
                
                请以JSON格式返回分析结果，包含：
                - is_malicious: bool
                - confidence: float
                - suspicious_attachments: list
                - risk_level: str
                - details: str
                """)
                
                chain = prompt | self.llm
                response = chain.invoke({"attachments": json.dumps(attachments)})
                
                llm_result = self._parse_llm_response(response.content)
                
                # 合并结果
                if suspicious_attachments:
                    llm_result["suspicious_attachments"] = suspicious_attachments
                
                return llm_result
            
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "suspicious_attachments": [],
                "risk_level": "low",
                "details": "未发现附件"
            }
            
        except Exception as e:
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "suspicious_attachments": [],
                "risk_level": "low",
                "details": f"附件检测错误: {str(e)}"
            }
    
    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """解析LLM的JSON响应"""
        try:
            # 提取JSON部分
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                # 如果无法解析JSON，返回默认结构
                return {
                    "is_malicious": False,
                    "confidence": 0.0,
                    "risk_level": "low",
                    "details": response[:500]
                }
        except:
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "risk_level": "low",
                "details": "无法解析分析结果"
            }
    
    def _enhance_header_detection(self, headers: Dict[str, Any], base_result: Dict[str, Any]) -> Dict[str, Any]:
        """增强头部检测的规则"""
        suspicious_indicators = base_result.get("suspicious_indicators", [])
        
        # 检查SPF
        if "spf" in str(headers).lower():
            if "fail" in str(headers).lower():
                suspicious_indicators.append("SPF验证失败")
        
        # 检查发件人域
        from_header = headers.get("From", "")
        if "reply-to" in headers and headers["reply-to"] != from_header:
            suspicious_indicators.append("回复地址与发件人不一致")
        
        base_result["suspicious_indicators"] = suspicious_indicators
        
        # 更新风险等级
        if len(suspicious_indicators) >= 2:
            base_result["risk_level"] = "high"
            base_result["confidence"] = max(base_result.get("confidence", 0), 0.8)
        
        return base_result
    
    def _enhance_content_detection(self, content: str, subject: str, base_result: Dict[str, Any]) -> Dict[str, Any]:
        """增强内容检测的规则"""
        suspicious_phrases = base_result.get("suspicious_phrases", [])
        
        # 关键词检测
        suspicious_keywords = [
            "立即行动", "紧急", "账户异常", "密码过期",
            "点击这里", "验证身份", "免费领取", "中奖"
        ]
        
        for keyword in suspicious_keywords:
            if keyword in content or keyword in subject:
                suspicious_phrases.append(f"包含可疑关键词: {keyword}")
        
        # 检查链接文本不匹配
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        urls = re.findall(url_pattern, content)
        
        base_result["suspicious_phrases"] = suspicious_phrases
        
        if len(suspicious_phrases) >= 3:
            base_result["risk_level"] = "high"
            base_result["confidence"] = max(base_result.get("confidence", 0), 0.7)
        
        return base_result
    
    def _is_suspicious_url(self, url: str) -> bool:
        """判断URL是否可疑"""
        suspicious_patterns = [
            r'bit\.ly', r'tinyurl\.', r'short\.',  # 短链接
            r'login\.', r'verify\.', r'secure\.',  # 钓鱼常用
            r'\.exe$', r'\.js$', r'\.vbs$'  # 可执行文件
        ]
        
        url_lower = url.lower()
        for pattern in suspicious_patterns:
            if re.search(pattern, url_lower):
                return True
        
        # IP地址直接访问
        ip_pattern = r'https?://\d+\.\d+\.\d+\.\d+'
        if re.match(ip_pattern, url_lower):
            return True
        
        return False
    
    def _get_url_suspicion_reason(self, url: str) -> str:
        """获取URL可疑原因"""
        reasons = []
        
        if re.search(r'bit\.ly|tinyurl\.', url.lower()):
            reasons.append("短链接服务")
        
        if re.search(r'\.exe$|\.js$|\.vbs$', url.lower()):
            reasons.append("可执行文件链接")
        
        if re.search(r'\d+\.\d+\.\d+\.\d+', url):
            reasons.append("直接IP地址访问")
        
        return "、".join(reasons) if reasons else "未知可疑特征"
    
    def _is_suspicious_attachment(self, attachment: Dict[str, Any]) -> bool:
        """判断附件是否可疑"""
        filename = attachment.get("filename", "").lower()
        filetype = attachment.get("filetype", "").lower()
        
        suspicious_extensions = [
            '.exe', '.bat', '.cmd', '.ps1', '.vbs',
            '.js', '.jar', '.zip', '.rar', '.7z'
        ]
        
        for ext in suspicious_extensions:
            if filename.endswith(ext):
                return True
        
        # 检查双重扩展名
        if re.search(r'\.[a-z]{3,4}\.[a-z]{2,4}$', filename):
            return True
        
        return False
    
    def get_all_tools(self):
        """获取所有工具"""
        return [
            Tool(
                name="header_detection",
                func=self.header_detection_agent,
                description="检测邮件头部的恶意特征"
            ),
            Tool(
                name="content_semantic_detection",
                func=self.content_semantic_agent,
                description="分析邮件内容的语义特征，检测钓鱼或恶意内容"
            ),
            Tool(
                name="url_detection",
                func=self.url_detection_agent,
                description="检测邮件中的可疑URL"
            ),
            Tool(
                name="attachment_detection",
                func=self.attachment_detection_agent,
                description="检测邮件附件中的恶意文件"
            )
        ]