from langchain_core.prompts import PromptTemplate, ChatPromptTemplate


def test_PromptTemplate():
    # 返回 PromptTemplate 对象
    prompt = PromptTemplate.from_template("你好，我是{name}，我今年{age}岁。")

    # 返回字符串
    res = prompt.invoke({"name": "张三","age": 18})
    print(f"测试 PromptTemplate ：{res.to_string()}")

def test_ChatPromptTemplate():
    # (role, content) role取值为："system", "human", or "ai"
    prompt = ChatPromptTemplate.from_messages([("system","你是一个电脑管家，你精通{os}系统。"),
                                               ("human","我的电脑为{os}系统，我想问你一些问题：{questions}")])
    in_dict = {"os": "Linux", "questions": "怎么清理缓存文件。"}
    res = prompt.format_messages(os="Linux",questions="怎么清理缓存文件。")
    print("format_messages 方法返回：",res)

    print('')

    res = prompt.invoke(in_dict)
    print("invoke 方法返回：",res.to_messages())

if __name__ == '__main__':
    test_PromptTemplate()
    print("="*60)
    test_ChatPromptTemplate()


