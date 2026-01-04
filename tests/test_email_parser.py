# tests/test.py
import sys
import os

# 添加 src 目录到 Python 路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

try:
    from utils import parse_eml_file, parse_eml_files
except ImportError as e:
    print(f"导入失败: {e}")

from email import policy
from email.parser import BytesParser
from email.message import EmailMessage, Message
import base64
import quopri
import json
from typing import Dict, Any, List

class EmailDebugger:
    """邮件调试工具"""
    
    @staticmethod
    def debug_email(raw_email: bytes) -> Dict[str, Any]:
        """调试邮件结构和内容"""
        try:
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)
            return EmailDebugger._analyze_message(msg)
        except Exception as e:
            return {"error": f"解析失败: {str(e)}"}
    
    @staticmethod
    def _analyze_message(msg: Message, indent: int = 0) -> Dict[str, Any]:
        """递归分析消息"""
        analysis = {}
        
        # 基本信息
        analysis["content_type"] = msg.get_content_type()
        analysis["is_multipart"] = msg.is_multipart()
        analysis["content_maintype"] = msg.get_content_maintype()
        analysis["content_subtype"] = msg.get_content_subtype()
        
        # 头部信息
        analysis["headers"] = {}
        for key, value in msg.items():
            analysis["headers"][key] = value
        
        # 特定头部
        analysis["filename"] = msg.get_filename()
        analysis["content_disposition"] = msg.get("Content-Disposition", "")
        analysis["content_id"] = msg.get("Content-ID", "")
        analysis["content_transfer_encoding"] = msg.get("Content-Transfer-Encoding", "7bit")
        analysis["charset"] = msg.get_content_charset()
        
        # 内容信息
        analysis["content_info"] = EmailDebugger._analyze_content(msg)
        
        # 子部分信息（如果是多部分）
        if msg.is_multipart():
            analysis["parts"] = []
            for i, part in enumerate(msg.get_payload()):
                part_analysis = EmailDebugger._analyze_message(part, indent + 1)
                part_analysis["part_index"] = i
                analysis["parts"].append(part_analysis)
        
        return analysis
    
    @staticmethod
    def _analyze_content(msg: Message) -> Dict[str, Any]:
        """分析消息内容"""
        content_info = {}
        
        try:
            # 获取原始载荷
            payload = msg.get_payload()
            content_info["payload_type"] = type(payload).__name__
            
            # 如果是列表（多部分）
            if isinstance(payload, list):
                content_info["payload_length"] = len(payload)
                content_info["is_list"] = True
            # 如果是字符串
            elif isinstance(payload, str):
                content_info["payload_length"] = len(payload)
                content_info["is_list"] = False
                content_info["payload_preview"] = payload[:200] + ("..." if len(payload) > 200 else "")
            # 其他情况
            else:
                content_info["payload_length"] = "unknown"
                content_info["is_list"] = False
            
            # 尝试解码内容
            try:
                decoded = msg.get_payload(decode=True)
                if decoded:
                    content_info["decoded_size"] = len(decoded)
                    
                    # 如果是文本类型，尝试显示内容
                    if msg.get_content_maintype() == "text":
                        charset = msg.get_content_charset() or 'utf-8'
                        try:
                            text = decoded.decode(charset, errors='ignore')
                            content_info["decoded_preview"] = text[:500] + ("..." if len(text) > 500 else "")
                            content_info["decoded_length"] = len(text)
                        except:
                            content_info["decoded_error"] = "解码失败"
                    else:
                        # 非文本内容，显示基本信息
                        content_info["is_binary"] = True
                        # 显示前几个字节的hex
                        hex_preview = ' '.join(f'{b:02x}' for b in decoded[:20])
                        content_info["hex_preview"] = hex_preview + ("..." if len(decoded) > 20 else "")
            except Exception as e:
                content_info["decode_error"] = str(e)
            
            # 尝试get_content方法
            try:
                content = msg.get_content()
                if content is not None:
                    content_info["get_content_type"] = type(content).__name__
                    if isinstance(content, str):
                        content_info["get_content_length"] = len(content)
                        content_info["get_content_preview"] = content[:200]
            except Exception as e:
                content_info["get_content_error"] = str(e)
                
        except Exception as e:
            content_info["analysis_error"] = str(e)
        
        return content_info
    
    @staticmethod
    def print_debug_info(debug_info: Dict[str, Any], indent: int = 0):
        """打印调试信息"""
        prefix = "  " * indent
        
        print(f"{prefix}{'='*60}")
        print(f"{prefix}邮件部分分析")
        print(f"{prefix}{'='*60}")
        
        # 基本信息
        print(f"{prefix}内容类型: {debug_info.get('content_type')}")
        print(f"{prefix}是否为多部分: {debug_info.get('is_multipart')}")
        print(f"{prefix}主类型/子类型: {debug_info.get('content_maintype')}/{debug_info.get('content_subtype')}")
        print(f"{prefix}文件名: {debug_info.get('filename', '无')}")
        print(f"{prefix}内容处置: {debug_info.get('content_disposition', '无')}")
        print(f"{prefix}Content-ID: {debug_info.get('content_id', '无')}")
        print(f"{prefix}传输编码: {debug_info.get('content_transfer_encoding')}")
        print(f"{prefix}字符集: {debug_info.get('charset', '无')}")
        
        # 内容信息
        content_info = debug_info.get("content_info", {})
        print(f"\n{prefix}内容分析:")
        for key, value in content_info.items():
            if key not in ["decoded_preview", "get_content_preview", "hex_preview"]:
                print(f"{prefix}  {key}: {value}")
        
        # 显示预览内容
        if "decoded_preview" in content_info:
            print(f"\n{prefix}解码预览:")
            print(f"{prefix}  {content_info['decoded_preview']}")
        
        if "get_content_preview" in content_info:
            print(f"\n{prefix}get_content预览:")
            print(f"{prefix}  {content_info['get_content_preview']}")
        
        if "hex_preview" in content_info:
            print(f"\n{prefix}Hex预览:")
            print(f"{prefix}  {content_info['hex_preview']}")
        
        # 递归处理子部分
        if "parts" in debug_info:
            print(f"\n{prefix}子部分 ({len(debug_info['parts'])} 个):")
            print(f"{prefix}{'-'*40}")
            for i, part in enumerate(debug_info["parts"]):
                print(f"\n{prefix}子部分 {i + 1}:")
                EmailDebugger.print_debug_info(part, indent + 2)



if __name__ == '__main__':

    file_path = r'D:\GitWork\phishing_email_detector\data\raw\[电子发票_ 271200085].eml'
    # res = parse_eml_file(file_path)
    # with open(file_path, 'rb') as f:
    #     raw_email = f.read()

    # EmailDebugger.print_debug_info(EmailDebugger.debug_email(raw_email))

    # print("分析结果字典：")
    # print(res)
    results = parse_eml_files(r'D:\GitWork\phishing_email_detector\data\raw')

