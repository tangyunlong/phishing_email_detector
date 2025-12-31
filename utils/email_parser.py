import re
from typing import Dict, Any, List
import email
from email import policy
from email.parser import BytesParser

class EmailParser:
    """邮件解析工具"""
    
    @staticmethod
    def parse_email(raw_email: bytes) -> Dict[str, Any]:
        """解析原始邮件"""
        try:
            # 解析邮件
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)
            
            # 提取头部
            headers = {}
            for key, value in msg.items():
                headers[key] = value
            
            # 提取主题
            subject = msg.get('Subject', '')
            
            # 提取正文
            body = EmailParser._extract_body(msg)
            
            # 提取URL
            urls = EmailParser._extract_urls(body)
            
            # 提取附件信息
            attachments = EmailParser._extract_attachments(msg)
            
            # 提取发件人信息
            from_header = msg.get('From', '')
            to_header = msg.get('To', '')
            
            return {
                "headers": headers,
                "subject": subject,
                "body": body,
                "urls": urls,
                "attachments": attachments,
                "from": from_header,
                "to": to_header,
                "raw_size": len(raw_email)
            }
            
        except Exception as e:
            raise Exception(f"邮件解析失败: {str(e)}")
    
    @staticmethod
    def _extract_body(msg) -> str:
        """提取邮件正文"""
        body = ""
        
        if msg.is_multipart():
            for part in msg.iter_parts():
                content_type = part.get_content_type()
                if content_type in ["text/plain", "text/html"]:
                    try:
                        body += part.get_content()
                    except:
                        pass
        else:
            body = msg.get_content()
        
        return str(body)
    
    @staticmethod
    def _extract_urls(text: str) -> List[str]:
        """从文本中提取URL"""
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        urls = re.findall(url_pattern, text)
        
        # 去重
        return list(set(urls))
    
    @staticmethod
    def _extract_attachments(msg) -> List[Dict[str, Any]]:
        """提取附件信息"""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.iter_parts():
                content_disposition = part.get("Content-Disposition", "")
                if "attachment" in content_disposition or part.get_filename():
                    attachment = {
                        "filename": part.get_filename() or "unknown",
                        "content_type": part.get_content_type(),
                        "size": len(part.get_content()),
                        "content_id": part.get("Content-ID", "")
                    }
                    attachments.append(attachment)
        
        return attachments
    
    @staticmethod
    def create_test_email() -> Dict[str, Any]:
        """创建测试邮件数据"""
        return {
            "headers": {
                "From": "suspicious@phishing.com",
                "To": "victim@example.com",
                "Subject": "紧急：您的账户需要验证",
                "Reply-To": "different@attacker.com",
                "Received": "from unknown.com by mail.server.com"
            },
            "subject": "紧急：您的账户需要验证",
            "body": """
            尊敬的客户，
            
            我们检测到您的账户存在异常活动。为了您的账户安全，请立即点击以下链接验证您的身份：
            
            http://bit.ly/verify-account-now
            
            如果不立即验证，您的账户将在24小时内被冻结。
            
            谢谢，
            安全团队
            """,
            "urls": [
                "http://bit.ly/verify-account-now",
                "http://malicious.com/download.exe"
            ],
            "attachments": [
                {"filename": "invoice.exe", "filetype": "application/exe", "size": 2048000},
                {"filename": "document.pdf", "filetype": "application/pdf", "size": 512000}
            ],
            "from": "suspicious@phishing.com",
            "to": "victim@example.com"
        }