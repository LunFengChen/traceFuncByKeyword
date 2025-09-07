# -*- coding: utf-8 -*-
# author: LunFengChen
# date: 2025-09-07
import sys
import os
import re
import idaapi
import idautils
import idc


class KeywordProcessor:
    """
    处理基于关键字的解析和过滤。
    """

    def parse_keywords(self, raw_keywords: str) -> list[list[str]]:
        """
        将原始关键字字符串解析为关键字组列表。
        ',' 在一个组内分隔关键字 (OR)。
        '|' 分隔组 (AND)。
        """
        piped_groups = raw_keywords.split('|')
        keyword_groups = []
        for group in piped_groups:
            comma_separated = [kw.strip() for kw in group.split(',')]
            keyword_groups.append(comma_separated)
        return keyword_groups

    def filter_functions(self, functions: list[tuple[int, str]],
                         keyword_groups: list[list[str]]) -> list[tuple[int, str]]:
        """
        根据用户输入的关键字组，通过链式过滤的方式筛选函数。
        每个关键字组（由'|'分隔）代表一个过滤阶段。
        在一个阶段内，多个关键字（由','分隔）是“或”关系。
        """
        # 初始函数列表为所有函数
        filtered_functions = functions
        # 遍历每个关键字组（过滤阶段）
        for i, group in enumerate(keyword_groups):
            # 如果组为空或只包含空字符串，则跳过此过滤阶段
            if not group or all(not s for s in group):
                continue

            # 用于存储当前阶段过滤结果的列表
            current_filter_results = []
            # 遍历上一阶段过滤后的函数列表
            for ea, name in filtered_functions:
                # 检查函数名是否匹配当前组内的任何一个关键字
                for keyword in group:
                    # 使用不区分大小写的子字符串匹配
                    if keyword.lower() in name.lower():
                        # 如果匹配成功，则将该函数加入当前结果列表，并跳出内层循环
                        current_filter_results.append((ea, name))
                        break
            
            # 更新过滤后的函数列表，为下一阶段做准备
            filtered_functions = current_filter_results

            # 根据用户要求，在每个过滤阶段后检查结果数量
            # 如果过滤后的函数数量小于等于200，则打印中间结果
            if len(filtered_functions) <= 200:
                print(f"--- 过滤阶段 {i+1} (关键字: {','.join(group)}) 后，找到 {len(filtered_functions)} 个函数 ---")
                for _, name in filtered_functions:
                    print(f"  [+] {name}")
                print("--- 结果打印完毕 ---")

        return filtered_functions


class IdaHelper:
    """
    IDA Pro API函数的包装器。
    """

    def get_all_functions(self) -> list[tuple[int, str]]:
        """
        从IDA数据库中检索所有函数。
        """
        return [(ea, idc.get_func_name(ea)) for ea in idautils.Functions()]

    def get_so_name(self) -> str:
        """
        获取当前加载文件的名称。
        """
        return idc.get_root_filename()

    def get_input_file_path(self) -> str:
        """
        获取输入文件的完整路径。
        """
        return idaapi.get_input_file_path()

    def ask_str(self, default: str, flags: int, prompt: str) -> str:
        """
        显示一个对话框，要求用户输入一个字符串。
        """
        try:
            import ida_kernwin
            return ida_kernwin.ask_str(default, flags, prompt)
        except ImportError:
            return idc.ask_str(default, flags, prompt)


class FridaCmdGenerator:
    """
    生成frida-trace命令。
    """

    def __init__(self):
        """
        初始化FridaCmdGenerator。
        """
        self.has_pyperclip = self._check_pyperclip()

    def _check_pyperclip(self) -> bool:
        """
        检查pyperclip模块是否可用。
        """
        try:
            import pyperclip
            return True
        except ImportError:
            print(
                "pyperclip模块不可用，无法自动复制到剪切板。如需此功能请在ida的python环境下执行命令安装：pip install pyperclip, 方法如下:"
            )
            print("1. 当前IDA使用的Python版本：", sys.version)
            print("2. 当前ida工作目录：", os.path.dirname(sys.executable),
                  "，请在此目录下寻找 python 目录，并使用其中的 pip.exe 执行上述安装命令。")
            return False

    def generate_and_output_command(self, functions: list[tuple[int, str]],
                                    so_name: str, keyword: str,
                                    save_dir: str):
        """
        生成frida-trace命令并输出。
        """
        if not functions:
            print("未找到符合条件的函数。")
            return

        result = [f"-a '{so_name}!0x{ea:X}'" for ea, name in functions]
        cmd_line = " ".join(result)

        safe_keyword = re.sub(r'[\\/:*?"<>|]', '_', keyword)
        output_file = os.path.join(save_dir,
                                   f"traceFuncByKeyword_{safe_keyword}.txt")

        func_names_file = os.path.join(
            save_dir, f"traceFuncByKeyword_func_{safe_keyword}.txt")

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(cmd_line)

        with open(func_names_file, "w", encoding="utf-8") as f:
            for _, name in functions:
                f.write(name + "\n")

        cmd1 = f"frida-trace -UF -O {output_file}"
        cmd2 = f"frida-trace -UF -O {output_file} -o {output_file}_log.log"

        if self.has_pyperclip:
            try:
                import pyperclip
                pyperclip.copy(cmd1)
                print("命令已复制到剪切板！")
            except Exception as e:
                print(f"复制到剪切板失败: {e}")

        print(f"共找到{len(functions)}个函数，frida-trace命令已导出到{output_file}")
        print(f"函数名已导出到{func_names_file}")
        print("1) 控制台显示: ", cmd1)
        print("2) 保存到日志: ", cmd2)


class TraceFuncByKeywordPlugin(idaapi.plugin_t):
    """
    TraceFuncByKeyword的主插件类。
    """
    flags = idaapi.PLUGIN_UNL
    comment = "通过关键字过滤函数生成frida-trace命令"
    help = "通过关键字跟踪函数并导出到txt,粘贴就能进行trace"
    wanted_name = "TraceFuncByKeyword"
    wanted_hotkey = "Ctrl+Shift+K"

    def init(self):
        """
        插件初始化。
        """
        print("根据关键词过滤, 支持链式过滤, 例如: 'encrypt,crypto|md5,sha,aes,rsa|sign,hash'")
        self.ida_helper = IdaHelper()
        self.keyword_processor = KeywordProcessor()
        self.cmd_generator = FridaCmdGenerator()
        return idaapi.PLUGIN_OK

    def run(self, arg):
        """
        插件的主要执行逻辑。
        """
        print("\n运行 TraceFuncByKeyword 插件!")
        keyword = self.ida_helper.ask_str("md5,sha|sign", 0,
                                          "输入关键词, e.g. 'md5,sha|sign' 或 're:^sign'")
        if not keyword:
            print("未输入关键词，退出。")
            return

        all_functions = self.ida_helper.get_all_functions()
        keyword_groups = self.keyword_processor.parse_keywords(keyword)
        filtered_functions = self.keyword_processor.filter_functions(
            all_functions, keyword_groups)

        so_name = self.ida_helper.get_so_name()
        input_path = self.ida_helper.get_input_file_path()
        save_dir = os.path.dirname(input_path)

        self.cmd_generator.generate_and_output_command(
            filtered_functions, so_name, keyword, save_dir)

    def term(self):
        """
        插件终止。
        """
        pass


def PLUGIN_ENTRY():
    """
    必需的插件入口点。
    """
    return TraceFuncByKeywordPlugin()


if __name__ == "__main__":
    print("请在IDA中作为插件运行此脚本。")