# -*- coding: utf-8 -*-
# author: LunFengChen
# date: 2025-09-06
import sys
import os

# ida提供的api
import idaapi
import idautils
import idc

class TraceFuncByKeywordPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Generate frida-trace command filtered by keyword"
    help = "Trace functions by keyword and export to txt"
    wanted_name = "TraceFuncByKeyword"
    wanted_hotkey = "Ctrl+Shift+K"

    def init(self):
        self.HAS_PYPERCLIP = False
        self.check_pyperclip()
        return idaapi.PLUGIN_OK

    def check_pyperclip(self):
        try:
            import pyperclip
            self.HAS_PYPERCLIP = True
        except ImportError:
            self.HAS_PYPERCLIP = False
            print(
                "pyperclip模块不可用，无法自动复制到剪切板。如需此功能请在ida的python环境下执行命令安装：pip install pyperclip, 方法如下:"
            )
            print("1. 前IDA使用的Python版本：", sys.version)
            print("2. 当前ida工作目录：", os.path.dirname(sys.executable), "，请在此目录下寻找 python 目录，并使用其中的 pip.exe 执行上述安装命令。")

    def ask_str_compat(self, default, flags, prompt):
        try:
            import ida_kernwin
            return ida_kernwin.ask_str(default, flags, prompt)
        except ImportError:
            return idc.ask_str(default, flags, prompt)

    def get_so_path_and_name(self):
        fullpath = idaapi.get_input_file_path()
        filepath, filename = os.path.split(fullpath)
        return filepath, filename

    def trace_func_by_keyword(self, keyword, output_file):
        result = []
        so_name = idc.get_root_filename()
        for ea in idautils.Functions():
            name = idc.get_func_name(ea)
            if keyword.lower() in name.lower():
                result.append(f"-a '{so_name}!0x{ea:X}'")
        cmd_line = " ".join(result)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(cmd_line)
        cmd1 = f"frida-trace -UF -O {output_file}"
        cmd2 = f"frida-trace -UF -O {output_file} -o {output_file}_log.log"
        if self.HAS_PYPERCLIP:
            try:
                import pyperclip
                pyperclip.copy(cmd1)
                print("命令已复制到剪切板！")
            except Exception as e:
                print(f"复制到剪切板失败: {e}")
        print("共找到{}个函数，已导出到{}".format(len(result), output_file))
        print("1) 控制台显示: ", cmd1)
        print("2) 保存到日志: ", cmd2)

    def run(self, arg):
        keyword = self.ask_str_compat("md5", 0, "输入关键词（如md5、sign、digest等）")
        if keyword:
            input_path = idaapi.get_input_file_path()
            save_dir = os.path.dirname(input_path)
            output_file = os.path.join(save_dir, f"traceFuncByKeyword_{keyword}.txt")
            self.trace_func_by_keyword(keyword, output_file)
        else:
            print("未输入关键词，退出。")

    def term(self):
        pass

def PLUGIN_ENTRY():
    return TraceFuncByKeywordPlugin()

if __name__ == "__main__":
    print("请在IDA中使用此脚本作为插件运行。 主要逻辑在TraceFuncByKeywordPlugin类的run中。")