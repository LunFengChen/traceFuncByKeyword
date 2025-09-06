import sys, os

# ida提供的api
import idaapi
import idautils
import idc

# 检查pyperclip是否可用
try:
    import pyperclip

    HAS_PYPERCLIP = True
except ImportError:
    HAS_PYPERCLIP = False
    print(
        "pyperclip模块不可用，无法自动复制到剪切板。如需此功能请在ida的python环境下执行命令安装：pip install pyperclip, 方法如下:"
    )
    print("1. 前IDA使用的Python版本：", sys.version)
    print("2. 当前ida工作目录：", os.path.dirname(sys.executable), "，请在此目录下寻找 python 目录，并使用其中的 pip.exe 执行上述安装命令。")



# 兼容新旧IDA的字符串输入
try:
    import ida_kernwin
    def ask_str_compat(default, flags, prompt):
        return ida_kernwin.ask_str(default, flags, prompt)
except ImportError:
    def ask_str_compat(default, flags, prompt):
        return idc.ask_str(default, flags, prompt)


# 核心函数
def traceFuncByKeyword(keyword, output_file):
    result = []
    so_name = idc.get_root_filename()  # 获取当前分析文件名
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if keyword.lower() in name.lower():
            # 生成frida-trace参数格式
            result.append(f"-a '{so_name}!0x{ea:X}'")
    cmd_line = " ".join(result)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(cmd_line)  # 一行输出所有参数

    cmd1 = f"frida-trace -UF -O {output_file}"
    cmd2 = f"frida-trace -UF -O {output_file} -o {output_file}_log.log"
    
    if HAS_PYPERCLIP:
        try:
            pyperclip.copy(cmd1)  # 自动复制到剪切板
            print("命令已复制到剪切板！")
        except Exception as e:
            print(f"复制到剪切板失败: {e}")
    print("共找到{}个函数，已导出到{}".format(len(result), output_file))
    print("1) 控制台显示: ", cmd1) # 输出frida-trace命令
    print("2) 保存到日志: ", cmd2) # 输出frida-trace命令


class TraceFuncByKeywordPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Generate frida-trace command filterd by keyword"
    help = "Trace functions by keyword and export to txt"
    wanted_name = "TraceFuncByKeyword"
    wanted_hotkey = "Ctrl+Shift+K"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        keyword = ask_str_compat("md5", 0, "输入关键词（如md5、sign、digest等）")
        if keyword:
            # 获取当前分析文件的完整路径
            input_path = idaapi.get_input_file_path()
            save_dir = os.path.dirname(input_path)
            output_file = os.path.join(save_dir, f"traceFuncByKeyword_{keyword}.txt")
            traceFuncByKeyword(keyword, output_file)
        else:
            print("未输入关键词，退出。")

    def term(self):
        pass


def PLUGIN_ENTRY():
    return TraceFuncByKeywordPlugin()

if __name__ == "__main__":
    print("请在IDA中使用此脚本作为插件运行。 主要逻辑在TraceFuncByKeywordPlugin类的run中。")
