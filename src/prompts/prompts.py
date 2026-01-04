
Header_Agent_Prompt = """
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
            """

Content_Agent_Prompt = """
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
            """

Url_Agent_Prompt = """
                分析以下URL列表，判断是否存在钓鱼或恶意链接风险：
                
                URL列表:
                {urls}
                
                请以JSON格式返回分析结果，包含：
                - is_malicious: bool
                - confidence: float
                - malicious_urls: list
                - risk_level: str
                - details: str
                """

Attachment_Agent_Prompt = """
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
                """