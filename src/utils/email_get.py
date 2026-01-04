import imaplib
import email
from email import policy
from email.parser import BytesParser
import os
from datetime import datetime, timedelta

class QQMailFetcher:
    def __init__(self, email_address, authorization_code):
        """
        初始化QQ邮箱获取器
        
        Args:
            email_address: QQ邮箱地址，如 '123456789@qq.com'
            authorization_code: 授权码，不是邮箱密码
        """
        self.email_address = email_address
        self.authorization_code = authorization_code
        self.imap_server = 'imap.qq.com'
        self.imap_port = 993
        
    def connect(self):
        """连接到QQ邮箱"""
        try:
            # 建立SSL连接
            self.mail = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            # 登录
            self.mail.login(self.email_address, self.authorization_code)
            print("✅ 成功连接到QQ邮箱")
            return True
        except Exception as e:
            print(f"❌ 连接失败: {e}")
            return False
    
    def fetch_recent_emails(self, limit=10, mailbox='INBOX'):
        """
        获取最近的邮件
        
        Args:
            limit: 获取的邮件数量
            mailbox: 邮箱文件夹，如 'INBOX'（收件箱）、'Sent'（已发送）等
        """
        if not hasattr(self, 'mail'):
            print("❌ 请先调用 connect() 方法连接邮箱")
            return []
        
        try:
            # 选择邮箱文件夹
            self.mail.select(mailbox)
            
            # 搜索所有邮件，按日期倒序排列
            status, messages = self.mail.search(None, 'ALL')
            if status != 'OK':
                print("❌ 搜索邮件失败")
                return []
            
            # 获取邮件ID列表
            email_ids = messages[0].split()
            
            # 取最新的limit封邮件
            recent_email_ids = email_ids[-limit:] if len(email_ids) > limit else email_ids
            recent_email_ids.reverse()  # 从新到旧排序
            
            emails_data = []
            
            for i, email_id in enumerate(recent_email_ids):
                print(f"📧 正在处理第 {i+1}/{len(recent_email_ids)} 封邮件...")
                
                # 获取邮件数据
                status, msg_data = self.mail.fetch(email_id, '(RFC822)')
                
                if status == 'OK':
                    # 解析邮件
                    raw_email = msg_data[0][1]
                    email_message = email.message_from_bytes(raw_email, policy=policy.default)
                    
                    # 提取邮件信息
                    email_info = self.extract_email_info(email_message, email_id)
                    emails_data.append(email_info)
            
            return emails_data
            
        except Exception as e:
            print(f"❌ 获取邮件失败: {e}")
            return []
    
    def fetch_emails_by_date(self, days=7, mailbox='INBOX'):
        """获取指定天数内的邮件"""
        if not hasattr(self, 'mail'):
            print("❌ 请先调用 connect() 方法连接邮箱")
            return []
        
        try:
            self.mail.select(mailbox)
            
            # 计算日期
            since_date = (datetime.now() - timedelta(days=days)).strftime('%d-%b-%Y')
            
            # 搜索指定日期之后的邮件
            status, messages = self.mail.search(None, f'(SINCE "{since_date}")')
            
            if status != 'OK':
                print("❌ 搜索邮件失败")
                return []
            
            email_ids = messages[0].split()
            email_ids.reverse()  # 从新到旧排序
            
            emails_data = []
            
            for i, email_id in enumerate(email_ids):
                print(f"📧 正在处理第 {i+1}/{len(email_ids)} 封邮件...")
                
                status, msg_data = self.mail.fetch(email_id, '(RFC822)')
                
                if status == 'OK':
                    raw_email = msg_data[0][1]
                    email_message = email.message_from_bytes(raw_email, policy=policy.default)
                    
                    email_info = self.extract_email_info(email_message, email_id)
                    emails_data.append(email_info)
            
            return emails_data
            
        except Exception as e:
            print(f"❌ 获取邮件失败: {e}")
            return []
    
    def extract_email_info(self, email_message, email_id):
        """从邮件消息中提取信息"""
        # 基本信息
        subject = email_message.get('Subject', '无主题')
        from_ = email_message.get('From', '未知发件人')
        to = email_message.get('To', '未知收件人')
        date = email_message.get('Date', '未知日期')
        message_id = email_message.get('Message-ID', '')
        
        # 提取正文
        text_body, html_body = self.extract_body(email_message)
        
        # 提取附件信息
        attachments = self.extract_attachments_info(email_message)
        
        return {
            'email_id': email_id.decode() if isinstance(email_id, bytes) else str(email_id),
            'message_id': message_id,
            'subject': subject,
            'from': from_,
            'to': to,
            'date': date,
            'text_body': text_body,
            'html_body': html_body,
            'attachments': attachments,
            'headers': dict(email_message.items())
        }
    
    def extract_body(self, email_message):
        """提取邮件正文"""
        text_parts = []
        html_parts = []
        
        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                # 跳过附件
                if "attachment" in content_disposition:
                    continue
                
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            text_parts.append(payload.decode(charset))
                        except:
                            text_parts.append(payload.decode('utf-8', errors='replace'))
                
                elif content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            html_parts.append(payload.decode(charset))
                        except:
                            html_parts.append(payload.decode('utf-8', errors='replace'))
        else:
            # 单部分邮件
            content_type = email_message.get_content_type()
            payload = email_message.get_payload(decode=True)
            if payload:
                charset = email_message.get_content_charset() or 'utf-8'
                try:
                    decoded = payload.decode(charset)
                except:
                    decoded = payload.decode('utf-8', errors='replace')
                
                if content_type == "text/plain":
                    text_parts.append(decoded)
                elif content_type == "text/html":
                    html_parts.append(decoded)
        
        return '\n'.join(text_parts), '\n'.join(html_parts)
    
    def extract_attachments_info(self, email_message):
        """提取附件信息（不下载，只获取信息）"""
        attachments = []
        
        if email_message.is_multipart():
            for part in email_message.walk():
                content_disposition = str(part.get("Content-Disposition"))
                
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            'filename': filename,
                            'content_type': part.get_content_type(),
                            'size': len(part.get_payload(decode=True)) if part.get_payload(decode=True) else 0
                        })
        
        return attachments
    
    def download_attachment(self, email_message, attachment_filename, download_dir="attachments"):
        """下载特定附件"""
        os.makedirs(download_dir, exist_ok=True)
        
        if email_message.is_multipart():
            for part in email_message.walk():
                content_disposition = str(part.get("Content-Disposition"))
                
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename == attachment_filename:
                        payload = part.get_payload(decode=True)
                        if payload:
                            filepath = os.path.join(download_dir, filename)
                            with open(filepath, 'wb') as f:
                                f.write(payload)
                            print(f"✅ 附件已下载: {filepath}")
                            return filepath
        
        print(f"❌ 未找到附件: {attachment_filename}")
        return None
    
    def close(self):
        """关闭连接"""
        if hasattr(self, 'mail'):
            try:
                self.mail.close()
                self.mail.logout()
                print("✅ 连接已关闭")
            except:
                pass

# 使用示例
def main():
    EMAIL_ADDRESS = '1833185295@qq.com'  # 例如：123456789@qq.com
    AUTHORIZATION_CODE = 'zgjmavjoyslmdgbj'     # 在QQ邮箱设置中获取
    
    # 创建获取器实例
    mail_fetcher = QQMailFetcher(EMAIL_ADDRESS, AUTHORIZATION_CODE)
    
    try:
        # 连接邮箱
        if mail_fetcher.connect():
            # 获取最近10封邮件
            print("🔄 正在获取最近10封邮件...")
            emails = mail_fetcher.fetch_recent_emails(limit=3)
            
            # 显示结果
            print(f"\n📊 共获取到 {len(emails)} 封邮件:")
            print("=" * 80)
            
            for i, email_data in enumerate(emails, 1):
                print(f"\n{i}. 主题: {email_data['subject']}")
                print(f"   发件人: {email_data['from']}")
                print(f"   时间: {email_data['date']}")
                print(f"   文本正文长度: {len(email_data['text_body'])} 字符")
                print(f"   HTML正文长度: {len(email_data['html_body'])} 字符")
                print(f"   附件数量: {len(email_data['attachments'])}")
                
                if email_data['attachments']:
                    print("   附件列表:")
                    for attachment in email_data['attachments']:
                        print(f"     - {attachment['filename']} ({attachment['size']} bytes)")
                
                print("-" * 80)
            
            # 可选：获取最近7天的邮件
            # print("\n🔄 正在获取最近7天的邮件...")
            # recent_emails = mail_fetcher.fetch_emails_by_date(days=7)
            # print(f"最近7天共有 {len(recent_emails)} 封邮件")
            
    except Exception as e:
        print(f"❌ 发生错误: {e}")
    finally:
        # 确保关闭连接
        mail_fetcher.close()

if __name__ == "__main__":
    main()