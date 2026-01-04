import json
from agents.central_agent import CentralControlAgent
from utils.email_parser import EmailParser
import sys
from email_config.email_config import email_config

def main(eml_path):
    """主程序"""
    print("=" * 60)
    print("恶意邮件检测多智能体系统")
    print("=" * 60)
    
    try:
        # 初始化中央控制智能体
        print("初始化智能体系统...")
        central_agent = CentralControlAgent()

        # 从EML文件解析
        with open(eml_path, 'rb') as f:
            raw_email = f.read()
        email_data = EmailParser.parse_email(raw_email)
        print(f"\n📧 已解析邮件: {email_data.get('subject', '无主题')}")
        
        # 显示邮件基本信息
        print("\n📨 邮件基本信息:")
        print(f"发件人: {email_data.get('from', '未知')}")
        print(f"收件人: {email_data.get('to', '未知')}")
        print(f"主题: {email_data.get('subject', '无主题')}")
        print(f"URL数量: {len(email_data.get('urls', []))}")
        print(f"附件数量: {len(email_data.get('attachments', []))}")
        
        # 开始分析
        input("\n按Enter键开始分析...")
        
        # 执行分析
        result = central_agent.analyze_email(email_data)
        
        # 显示结果
        print("\n" + "=" * 60)
        print("分析结果")
        print("=" * 60)
        
        decision = result["final_decision"]
        
        # 最终判断
        if decision.get("is_malicious", False):
            print(f"🚨 检测到恶意邮件!")
            print(f"威胁类型: {decision.get('threat_type', '未知')}")
            print(f"风险等级: {decision.get('risk_level', '未知')}")
            print(f"置信度: {decision.get('confidence', 0):.2%}")
        else:
            print("✅ 邮件安全")
            print(f"风险等级: {decision.get('risk_level', '低')}")
        
        # 恶意组件
        malicious_components = decision.get("malicious_components", [])
        if malicious_components:
            print(f"恶意组件: {', '.join(malicious_components)}")
        
        # 建议
        recommendations = decision.get("recommendations", [])
        if recommendations:
            print("\n💡 建议措施:")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")
        
        # 摘要
        summary = decision.get("summary", "")
        if summary:
            print(f"\n📋 摘要: {summary}")
        
        # 是否需要人工审核
        if result.get("need_human_review", False):
            print("\n⚠️  需要人工审核: 高风险但置信度较低")
        
        # 保存结果
        save_choice = input("\n是否保存结果到文件？ (y/n): ").lower()
        if save_choice == 'y':
            filename = f"email_analysis_{hash(json.dumps(email_data))}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"结果已保存到: {filename}")
        
        # 显示详细信息
        detail_choice = input("\n是否显示详细信息？ (y/n): ").lower()
        if detail_choice == 'y':
            print("\n📊 详细信息:")
            for component, comp_result in result["component_results"].items():
                print(f"\n{component.upper()}检测:")
                print(f"  恶意: {comp_result.get('is_malicious', False)}")
                print(f"  风险等级: {comp_result.get('risk_level', 'low')}")
                if 'details' in comp_result:
                    details = comp_result['details'][:200] + "..." if len(comp_result['details']) > 200 else comp_result['details']
                    print(f"  详情: {details}")
        
        print("\n🎯 分析完成!")
        
    except KeyboardInterrupt:
        print("\n\n用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ 发生错误: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    file_path = r'D:\GitWork\phishing_email_detector\data\raw\[电子发票_ 271200085].eml'
    main(file_path)