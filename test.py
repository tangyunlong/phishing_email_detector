# 快速测试
from agents.central_agent import CentralControlAgent
from utils.email_parser import EmailParser

# 初始化
central_agent = CentralControlAgent()

# 测试邮件
test_email = EmailParser.create_test_email()

# 分析
result = central_agent.analyze_email(test_email)

# 查看结果
print(f"是否为恶意邮件: {result['final_decision']['is_malicious']}")
print(f"风险等级: {result['final_decision']['risk_level']}")