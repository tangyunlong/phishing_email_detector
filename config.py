import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # DeepSeek API配置
    DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
    DEEPSEEK_API_BASE = "https://api.deepseek.com/v1"
    
    # 智能体配置
    AGENT_TEMPERATURE = 0.1
    
    # 检测阈值
    DETECTION_THRESHOLD = 0.7
    SUSPICIOUS_THRESHOLD = 0.4
    
config = Config()