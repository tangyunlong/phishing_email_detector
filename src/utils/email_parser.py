import re
import sys
from email import policy
from email.parser import BytesParser
from email.header import decode_header
from typing import Dict, Any, List
from pathlib import Path


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
            
            # 提取正文 - 使用改进的方法
            body = EmailParser._extract_body_safe(msg)
            
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
    def _extract_body_safe(msg) -> str:
        """安全的正文提取方法，处理单部分和多部分邮件"""
        body = ""
        
        try:
            # 检查是否是单部分邮件
            if not msg.is_multipart():
                # 单部分邮件，直接获取内容
                content = msg.get_content()
                if isinstance(content, str):
                    body = content
                elif isinstance(content, bytes):
                    # 尝试解码字节内容
                    charset = msg.get_content_charset() or 'utf-8'
                    try:
                        body = content.decode(charset, errors='ignore')
                    except:
                        body = str(content, errors='ignore')
                elif content is not None:
                    body = str(content)
                return body
            
            # 多部分邮件，遍历所有部分
            for part in msg.walk():  # 使用walk()而不是iter_parts()
                content_type = part.get_content_type()
                
                # 只处理文本内容，跳过附件
                if content_type in ["text/plain", "text/html"]:
                    # 检查是否是附件
                    content_disposition = str(part.get("Content-Disposition", ""))
                    if "attachment" in content_disposition.lower():
                        continue
                    
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            body_content = content
                        elif isinstance(content, bytes):
                            charset = part.get_content_charset() or 'utf-8'
                            body_content = content.decode(charset, errors='ignore')
                        else:
                            body_content = str(content)
                        
                        # 添加分隔符
                        if body and body_content:
                            body += "\n---\n"
                        body += body_content
                    except Exception as e:
                        # 记录错误但继续处理其他部分
                        print(f"解析部分内容时出错: {e}")
                        continue
        
        except Exception as e:
            print(f"提取正文时出错: {e}")
            body = f"正文提取失败: {str(e)}"
        
        return body or "无正文内容"
    
    @staticmethod
    def _extract_urls(text: str) -> List[str]:
        """从文本中提取URL"""
        if not text:
            return []
        
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        urls = re.findall(url_pattern, text)
        
        # 去重
        return list(set(urls))
    
    @staticmethod
    def _extract_attachments(msg) -> List[Dict[str, Any]]:
        """提取附件信息"""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():  # 使用walk()确保遍历所有部分
                content_disposition = part.get("Content-Disposition", "")
                filename = part.get_filename()
                
                # 检查是否是附件
                is_attachment = (
                    "attachment" in str(content_disposition).lower() or 
                    (filename and not part.is_multipart())
                )
                
                if is_attachment:
                    try:
                        # 获取附件大小
                        payload = part.get_payload(decode=True)
                        size = len(payload) if payload else 0
                    except:
                        size = 0
                    
                    attachment = {
                        "filename": filename or "unknown",
                        "content_type": part.get_content_type(),
                        "size": size,
                        "content_id": part.get("Content-ID", ""),
                        "content_disposition": str(content_disposition)
                    }
                    attachments.append(attachment)
        
        return attachments
    
    
# 读取单个eml文件并解析
def parse_eml_file(file_path):
    """读取eml文件并解析"""
    try:
        # 以二进制方式读取eml文件
        with open(file_path, 'rb') as f:
            raw_email = f.read()
        
        # 解析邮件
        parsed_data = EmailParser.parse_email(raw_email)
        
        # 输出解析结果
        print(f"邮件主题: {parsed_data['subject']}")
        print(f"发件人: {parsed_data['from']}")
        print(f"收件人: {parsed_data['to']}")
        print(f"正文长度: {len(parsed_data['body'])}")
        print(f"URL数量: {len(parsed_data['urls'])}")
        print(f"附件数量: {len(parsed_data['attachments'])}")
        
        # 显示所有URL
        if parsed_data['urls']:
            print("\n邮件中的URL:")
            for url in parsed_data['urls']:
                print(f"  - {url}")
        
        # 显示附件信息
        if parsed_data['attachments']:
            print("\n邮件附件:")
            for att in parsed_data['attachments']:
                print(f"  - {att['filename']} ({att['content_type']}, {att['size']} bytes)")
        return parsed_data
        
    except Exception as e:
        print(f"解析失败: {str(e)}")
        return None

def parse_eml_files(directory):
    results = []
    directory = Path(directory)
    eml_files = list(directory.glob("*eml"))
    print("="*70)
    for eml_file in eml_files:
        try:
            result = parse_eml_file(eml_file)
            results.append(result)
            print(f"已解析{eml_file.name}")
            print("="*70)
        except Exception as e:
            print(f"解析失败 {eml_file.name} : {str(e)}")

    return results


if __name__ == '__main__':
    pass