# traceFuncByKeyword

一个简单的IDA 插件，可根据关键字快速筛选函数，支持链式过滤，并一键生成 `frida-trace` 命令，提升大型so的逆向分析效率。
**快捷键**: `Ctrl+Shift+K` (K -> Keyword)


## 过滤规则示例
链式过滤规则, `,`表示或, `|`表示且(过滤), 以`encrypt,crypto|md5,sha,aes,rsa|sign,hash`为例：
1. 先过滤包含`encrypt`或`crypto`的函数
2. 再从上一步结果中，过滤包含`md5`或`sha`或`aes`或`rsa`的函数
3. 再从上一步结果中，过滤包含`sign`或`hash`的函数

---

## 功能亮点

- **强大的链式过滤**: 使用 `|` 分隔符实现多阶段过滤，逐步缩小函数范围。
- **灵活的关键字匹配**: 在每个过滤阶段，使用 `,` 分隔多个关键字（"或"关系），进行不区分大小写的子字符串匹配。
- **详细的日志输出**: 在 IDA 输出窗口中，过滤操作的详细日志和中间结果。
- **一键生成命令**: 自动生成 `frida-trace` 命令，并将其复制到剪贴板。
- **导出函数列表**: 将最终筛选出的函数符号列表和函数地址偏移保存到文件中，方便后续处理。

---

## 使用方法

1.  **安装**:
    -   找到 `ida.exe` 的安装目录。
    -   进入上一级的 `plugins` 目录。
    -   将 `traceFuncByKeyword.py` 文件放入该目录。
    -   重启 IDA Pro。

2.  **运行**:
    -   在 IDA 中打开目标文件后，按下快捷键 `Ctrl+Shift+K`。
    -   在弹出的输入框中输入您的过滤关键字。
    -   键入 `Enter` 过滤;

---

## 反馈

-   提交 [Issue](https://github.com/your-repo/traceFuncByKeyword/issues)
-   加入 QQ 交流群: 686725227


---

## 参考
1. [Pr0214/trace_natives](https://github.com/Pr0214/trace_natives)