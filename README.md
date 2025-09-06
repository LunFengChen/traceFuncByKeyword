# traceFuncByKeyword
作用：ida插件，根据关键词去筛选需要的函数，并生成`frida-trace`命令，复制到剪切板


原理：
1. 利用ida提供的python-api获取所有函数
2. 根据关键词进行过滤
3. 再按照`frida-trace`工具的参数规则，生成批量trace命令

来由：
- flutter案例的`libapp.so`有些，关键词过滤之后太多了，比如40/50个函数这种，然后肉眼去过滤很烦人；
- ida插件练手用的，为后面的自动化去ollvm混淆插件做一些铺垫(但感觉之后也搞不出来hhh)


评价: 没啥diao用


使用：找到ida.exe所在目录，退到上一级，寻找到plugins目录，然后下载release中的py文件，丢进去，重启ida即可。


反馈：issue或者进q群：686725227反馈；
