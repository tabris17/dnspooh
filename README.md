# Dnspooh

Dnspooh 是一个轻量级 DNS 中继和代理服务器，可以为本机或本地网络提供安全的 DNS 解析服务，并可以通过设置屏蔽指定的域名和解析结果。

## 1. 安装和运行

运行 Dnspooh 需要 Python 3.11 及以上版本。

### 1.1 pip 安装

```shell
pip install dnspooh
python -m dnspooh
```

### 1.2 源代码运行

```shell
git clone https://githu.com/tabris17/dnspooh
cd dnspooh
pip install -r requirements.txt
python main.py
```

### 1.3 打包

（等待）

## 2. 使用方法

运行 `python -m dnspooh --help` 或 `python main.py --help` 可以查看 Dnspooh 支持的命令行参数：

```text
usage: DNSPooh [-c file] [-u servers [servers ...]] [-t ms] [-h host] [-p port] [-D] [-d] [-v] [--help]

A MitM DNS Proxy

options:
  -c file, --config file
                        config file path (example "config.yml")
  -u servers [servers ...], --upstream servers [servers ...]
                        space-separated upstream DNS servers list
  -t ms, --timeout ms   milliseconds for upstream DNS response timeout (default 5 ms)
  -h host, --host host  local DNS proxy server listening host (default "0.0.0.0")
  -p port, --port port  local DNS proxy server listening port (default "53")
  -D, --debug           display debug message
  -d, --dump            dump pretty config data
  -v, --version         show program's version number and exit
  --help                show this help message and exit
```



## 3. 自定义规则

规则分为： if/then 规则、 if/before 、if/after 和 if/before/after 规则。前者用于直接返回 DNS 结果，而无需请求上游服务器，通常用于屏蔽或自定义域名解析；后者可以指定上游服务器，以及处理上游服务器的返回结果。

每种规则都可以设置 end 块来表示命中该规则是否继续下一条规则判断， end 块的值是布尔类型。

### if/then 规则

在所有类型的规则中， if/then 规则只能命中一次，后续的 if/then 规则都将会被跳过。then 块用来直接返回 DNS 请求结果，而不再将请求转给上游服务器。

### if/before 规则

before 块用于指定上游服务器，或者替换请求中的域名。

### if/after 规则

after 块用于过滤响应的解析结果。

### if/before/after 规则

结合了 if/before 规则和 if/after 规则。

### 规则块

#### if

if 由一个或多个判断条件组成的逻辑运算表达式。支持的判断条件有：

- domain is *domain*
- domain is (*domain1*, *domain2*, ...)
- domain is not *domain*
- domain is not (*domain1*, *domain2*, ...)
- *keyword* in domain
- (*keyword1*, *keyword2*, ...) in domain
- *keyword* not in domain
- (*keyword1*, *keyword2*, ...) not in domain
- domain starts with *prefix*
- domain starts with (*prefix1*, *prefix2*, ...)
- domain starts without *prefix*
- domain starts without (*prefix1*, *prefix2*, ...)
- domain ends with *suffix*
- domain ends with (*suffix1*, *suffix2*, ...)
- domain ends without *suffix*
- domain ends without (*suffix1*, *suffix2*, ...)
- domain match /*regex*/

支持的逻辑运算按优先级排列如下：

- not *expr*
- *expr* and *expr*
- *expr* or *expr*

#### then

- block
- return *ip*
- return (*ip1*, *ip2*, ...)

#### before

- set upstream group to *name*
- set upstream name to *name*
- replace domain by *domain*

#### after

- block if *expr1*
- return *ip* if *expr1*
- return (*ip1*, *ip2*, ...) if *expr1*
- add record *ip*
- add record (*ip1*, *ip2*, ...)
- add record *ip* if *expr1*
- add record (*ip1*, *ip2*, ...) if *expr1*
- remove record where *expr2*
- replace record by *ip* where *expr2*
- run *command* where *expr2*

expr1 支持的判断条件有：

- any ip is *ip*
- any ip is (*ip1*, *ip2*, ...)
- any ip is not *ip*
- any ip is not (*ip1*, *ip2*, ...)
- any ip in *cidr*
- any ip in (*cidr1*, *cidr2*, ...)
- any ip not in *cidr*
- any ip not in (*cidr1*, *cidr2*, ...)
- any geoip is *country*
- any geoip is not *country*
- all ip is *ip*
- all ip is (*ip1*, *ip2*, ...)
- all ip is not *ip*
- all ip is not (*ip1*, *ip2*, ...)
- all ip in *cidr*
- all ip in (*cidr1*, *cidr2*, ...)
- all ip not in *cidr*
- all ip not in (*cidr1*, *cidr2*, ...)
- all geoip is *country*
- all geoip is not *country*

expr2 支持的判断条件有：

- ip is *ip*
- ip is (*ip1*, *ip2*, ....)
- ip is not *ip*
- ip is not (*ip1*, *ip2*, ....)
- ip in *cidr*
- ip in (*cidr1*, *cidr2*, ...)
- ip not in *cidr*
- ip not in (*cidr1*, *cidr2*, ...)
- geoip is *country*
- geoip is not *country*
- first
- last
