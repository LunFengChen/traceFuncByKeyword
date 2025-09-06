# traceFuncByKeyword
作用：ida插件，根据关键词去筛选需要的函数，并生成frida-trace命令

原理：利用ida提供的python-api获取所有函数，然后根据关键词进行过滤，然后再按照frida-trace工具的参数规则，生成命令进行批量hook
来由：
- flutter案例有些，关键词过滤之后太多了，比如40/50个函数这种，然后肉眼去过滤很烦人；
- ida插件练手用的，为后面的自动化去ollvm混淆做铺垫(但感觉也搞不出来hhh)
评价: 没啥diao用
