# Dnspooh

Dnspooh 是一个轻量级 DNS 中继和代理服务器，可以为本机或本地网络提供安全的 DNS 解析服务，支持代理服务器、 hosts 文件、域名和 IP 黑名单，以及自定义规则。

## 1. 安装和运行

Dnspooh 使用 Python 语言编写，运行 Dnspooh 需要 Python 3.10 及以上版本。程序能以 Python 模块的方式运行，也能以源代码的方式直接运行。此外，项目还提供了打包后的 Windows 可执行文件。

### 1.1 Python 模块

通过 pip 安装模块：

```shell
pip install dnspooh
```

运行 Dnspooh ：

```shell
dnspooh --help
```

或者：

```shell
python -m dnspooh --help
```

### 1.2 源代码

```shell
git clone https://githu.com/tabris17/dnspooh
cd dnspooh
pip install -r requirements.txt
```

运行 Dnspooh ：

```shell
python main.py --help
```

### 1.3 可执行文件

将[下载](https://github.com/tabris17/dnspooh/releases)的 `dnspooh-vX.Y.Z-win-amd64.zip` （其中 X.Y.Z 是版本号）文件解压缩保存在本地，运行其中的 `dnspooh.exe` 可执行文件。

## 2. 使用方法

直接运行 dnspooh 将以默认配置启动服务。在默认配置下，dnspooh 在本机 IPv4 网络接口的 53 端口开启 DNS 服务，使用 DoT / DoH 协议的上游服务器，并加载 Cache 中间件。

### 2.1 命令行参数

通过命令行的 `--help` 参数可以查看 Dnspooh 支持的命令行参数：

```text
usage: dnspooh [-c file] [-u dns_server [dns_server ...]] [-t ms] [-l addr [addr ...]] [-S] [-6] [-D] [-d] [-v] [-h]

A Lightweight DNS MitM Proxy

options:
  -c file, --config file
                        config file path (example "config.yml")
  -u dns_server [dns_server ...], --upstream dns_server [dns_server ...]
                        space-separated upstream DNS servers list
  -t ms, --timeout ms   milliseconds for upstream DNS response timeout (default 5000 ms)
  -l addr [addr ...], --listen addr [addr ...]
                        binding to local address and port for DNS proxy server (default "0.0.0.0:53")
  -S, --secure-only     use DoT/DoH upstream servers only
  -6, --enable-ipv6     enable IPv6 upstream servers
  -D, --debug           display debug message
  -d, --dump            dump pretty config data
  -v, --version         show program's version number and exit
  -h, --help            show this help message and exit
```

可以通过命令行参数和配置文件来对程序进行设置。通过命令行参数传递的设置优先级高于配置文件中对应的设置。如果没有指定配置文件，程序启动后会尝试加载当前目录下的 `config.yml` 配置文件。

| 命令行参数                     | 描述                                 | 例子                               |
| ------------------------------ | ------------------------------------ | ---------------------------------- |
| -c file                        | 加载配置文件                         | dnspooh -c config.yml              |
| -u dns_server [dns_server ...] | 上游服务器地址列表                   | dnspooh -u 114.114.114.114 1.1.1.1 |
| -t ms                          | 设置上游服务器超时时间（单位：毫秒） |                                    |
| -l addr [addr ...]             | 绑定本地网络地址列表                 | dnspooh -l 0.0.0.0 [::]            |
| -D                             | 输出调试信息                         |                                    |
| -S                             | 仅使用 DoT/DoH 协议的上游服务器      |                                    |
| -6                             | 启用 IPv6 服务器                     |                                    |
| -d                             | 打印当前配置信息                     | dnspooh -c config.yml -d           |
| -v                             | 显示程序当前版本号                   |                                    |
| -h                             | 打印帮助信息                         |                                    |

在命令行中设置的上游服务器地址列表，会替换程序内置的地址列表。上游服务器地址格式有如下几种：

- DNS 服务器  
  IP 地址。特别地，如果是 IPv6 地址，需要用 `[]` 包裹。例如：`1.1.1.1` ， `[2606:4700:4700::1111]`
- DoH 服务器  
  URL 链接。例如：`https://1.1.1.1/dns-query`
- DoT 服务器  
  IP 地址加 853 端口。例如：`1.1.1.1:853`

### 2.2 配置文件

Dnspooh 使用的配置文件为 YAML 格式。一个常规的配置文件如下：

```yaml
proxy: http://127.0.0.1:8080

hosts:
  - !path hosts
  - https://raw.hellogithub.com/hosts

block:
  - !path block.txt

rules:
  - !include cn-domain.yml

middlewares:
  - rules
  - hosts
  - block
  - cache
  - log
```

配置文件支持 `!path` 和 `!include` 两个扩展指令。当配置项目是一个文件名时，使用 `!path` 指令表示以当前配置文件所在路径作为文件相对路径的起始位置，如果不使用 `!path` 指令，则以程序运行路径作为文件相对路径的起始位置。 `!include` 指令用来引用外部 yaml 配置文件，当前配置文件的所在路径作为被引用配置文件相对路径的起始位置。

| 配置名         | 数据类型 | 默认         | 描述                                                         |
| -------------- | -------- | ------------ | ------------------------------------------------------------ |
| debug          | Boolean  | false        | 控制台/终端是否输出调试信息                                  |
| listen         | String/Array | "0.0.0.0:53" | 服务绑定本机地址。此项可以是一个字符串或一个数组 |
| geoip          | String   |              | GeoIP2 数据库文件路径。默认使用 [GeoIP2-CN](https://github.com/Hackl0us/GeoIP2-CN) |
| secure         | Boolean  | false        | 仅使用安全（DoH / DoT）的上游 DNS 服务器                     |
| ipv6 | Boolean | false | 启用 IPv6 地址的上游 DNS 服务器 |
| timeout        | Integer  | 5000          | 上游 DNS 服务器响应超时时间（单位：毫秒）                      |
| proxy          | String   |              | 代理服务器，支持 HTTP 和 SOCKS5 代理                         |
| upstreams | Array | | 替换内置上游 DNS 服务器列表 |
| upstreams+ | Array | | 追加到内置上游 DNS 服务器列表 |
| upstreams_filter |  | | 筛选出可用的上游 DNS 服务器 |
| upstreams_filter.name | Array | | 筛选出名称存在于此列表中的服务器 |
| upstreams_filter.group | Array | | 筛选出分组存在于此列表中的服务器 |
| middlewares    | Array    | ["cache"]    | 启用的中间件。列表定义顺序决定加载顺序                       |
| rules          | Array    |              | 自定义规则列表                                               |
| hosts          | Array    |              | hosts 文件列表。支持 http/https 链接                         |
| block          | Array    |              | 黑名单文件列表。支持 http/https 链接                         |
| cache          |          |              | 缓存配置                                                     |
| cache.max_size | Integer  | 4096         | 最大缓存条目数                                               |
| cache.ttl      | Integer  | 86400        | 缓存有效期（单位：秒）                                       |
| log.path       | String   | "access.log" | 访问日志的文件路径，日志文件为 SQLite3 数据库格式            |
| log.trace      | Boolean  | true         | 是否记录调试跟踪信息                                         |
| log.payload    | Boolean  | true         | 是否记录 DNS 请求和响应的数据                                |

下面的配置文件用于追加上游 DNS 服务器：

```yaml
upstreams+:
  - name: my-dns
    host: 192.168.1.1
    proxy: http://192.168.1.1
    timeout: 5000
    disable: false
    priority: 0
    groups:
      - my
      - cn

  - name: my-dot
    host: 192.168.1.1
    type: tls

  - name: my-doh
    url: https://my-doh/dns-query
```

其中 `proxy` 、 `timeout` 、 `disable` 、 `priority` 和 `groups` 都是可选项。

### 2.1 中间件

Dnspooh 提供下列中间件：

1. Rules 自定义规则

2. Hosts 自定义域名解析

3. Block 域名和 IP 地址黑名单

4. Cache 缓存上游服务器的解析结果

5. Log 数据库型日志

这些中间件可以在配置文件中开启。在默认配置下，仅启用 Cache 中间件。中间件采用装饰器模式，先加载的中间件处于封装内层，后加载的中间件处于外层。建议按照本文档中的列表顺序定义。

其中 `block` 和 `hosts` 的配置是一组文件列表。文件可以是本地文件，也可以是 http/https 链接。且当文件是链接时，还能设置更新频率：

```yaml
hosts:
  - [https://raw.hellogithub.com/hosts, 3600]
```

上面的配置表示，程序每隔 3600 秒重新载入一次 https://raw.hellogithub.com/hosts 的数据。

## 3. 自定义规则

通过自定义规则中间件，可以实现按条件屏蔽域名、自定义解析结果等操作。可以在配置文件的 `rules` 单元中设置一组或多组规则，每组规则由 `if` 、 `then` 、 `before` 、 `after` 、 `end` 字段组合而成。根据不同的需求，一组规则可以由 `if/then/end` 字段组成；或者由 `if/before/after/end` 字段组成。其中 `end` 字段是可选的，表示命中并处理完此条规则后是否停止处理后续规则，默认值为 `false` ； `if` 字段是一个表达式，当表达式结果为真时，则表示命中这条规则； `then` 字段是一条语句，可以在此处直接拦截 DNS 解析请求，直接返回 NXDOMAIN （域名不存在）或自定义解析结果，而不会将请求转发到上游服务器； `before` 字段是一组逗号分隔的命令语句，在 DNS 解析请求被转发到上游服务器之前被处理，可以用于指定上游服务器以及替换请求中的域名； `after` 字段也是一组逗号分隔的命令语句，在 DNS 解析结果从上游服务器返回之后被处理，可以根据返回的结果进行修改操作或执行外部命令。

配置例子：

```yaml
rules:
  - if: (lianmeng, adwords, adservice) in domian
    then: block
    end: true

  - if: domain ends with (.cn, .top)
    before: set upstream group to cn

  - if: always
    before: set upstream group to adguard
    after: run "sudo route add {ip} mask 255.255.255.255 192.168.1.1" where geoip is cn
```

上面的配置作用是：

1. 屏蔽含有 lianmeng 、 adwords 、 adservice 关键字的域名；
2. 让 .cn 和 .top 域名使用国内的 DNS 服务器解析；
3. 默认使用 adguard 作为上游域名解析服务器。adguard 服务器可以屏蔽所有广告域名；
4. 当返回的解析结果中包含国内 IP 时，将此 IP 加入本机路由表，使用 192.168.1.1 网关路由（当开启全局 VPN 时，使用本地网络访问国内 IP ）。

所有的表达式都支持 `not` 、 `and` 和 `or` 逻辑运算，按优先级排列如下：

1. not *expr*
2. *expr* and *expr*
3. *expr* or *expr*

可以用圆括号运算符 `(` 与 `)` 来改变逻辑运算符的优先级。

```yaml
rules:
  - if: (domain ends with .cn or domain ends with .top) and not blog in domain
    then: block
    end: true
```

上面的配置作用是，如果是 .cn 或 .top 域名，且域名中没有包含 blog 关键字，则屏蔽。

### 3.1 if 表达式

if 字段由一个或多个判断条件组成的逻辑运算表达式。支持的判断条件有：

- domain is *domain*  
  域名等于 *domain*
- domain is (*domain1*, *domain2*, ...)  
  域名与列表中任一 *domain* 相等，等价于 domain is *domain1* or domain is *domain2* or ... 
- domain is not *domain*  
  域名不等于 *domain* ，等价于 not domain is *domain*
- domain is not (*domain1*, *domain2*, ...)  
  域名不等于列表中的任何 *domain* ，等价于 domain is not *domain1* and domain is not *domain2* and ...
- *keyword* in domain  
  域名包含 *keyword*
- (*keyword1*, *keyword2*, ...) in domain  
  域名包含列表中任一 *keyword* ，等价于 *keyword1* in domain or *keyword2* in domain or ...
- *keyword* not in domain  
  域名不包含 *keyword* ，等价于 not *keyword* in domain
- (*keyword1*, *keyword2*, ...) not in domain  
  域名不包含列表中的任何 *keyword* ，等价于 *keyword1* not in domain and *keyword2* not in domain and ...
- domain starts with *prefix*  
  域名前缀为 *prefix*
- domain starts with (*prefix1*, *prefix2*, ...)  
  域名前缀是列表中的任一 *prefix* ，等价于 domain starts with *prefix1* or domain starts with *prefix2* or ...    
- domain starts without *prefix*  
  域名前缀不为 *prefix* ，等价于 not domain starts with *prefix*  
- domain starts without (*prefix1*, *prefix2*, ...)  
  域名前缀不为列表中的任何 *prefix* ，等价于 domain starts without *prefix1* and domain starts without *prefix2* and ...
- domain ends with *suffix*  
  域名后缀为 *suffix*
- domain ends with (*suffix1*, *suffix2*, ...)  
  域名后缀为列表中的任一 *suffix* ，等价于 domain starts with *suffix1* or domain starts with *suffix2* or ...    
- domain ends without *suffix*  
  域名后缀不为 *suffix* ，等价于 not domain ends with *suffix*  
- domain ends without (*suffix1*, *suffix2*, ...)  
  域名后缀不为列表中的任何 *suffix* ，等价于 domain ends without *suffix1* and domain ends without *suffix2* and ...    
- domain match /*regex*/  
  域名完整匹配正则表达式 *regex*
- always  
  总是为真

### 3.2 then 语句

then 字段可以是下列任意语句之一：

- block  
  屏蔽当前请求
- return *ip*  
- return (*ip1*, *ip2*, ...)  
  直接返回解析结果

### 3.3 before 语句

before 字段由下列一条或多条逗号分隔的语句组成：

- set upstream group to *name*  
  使用 *name* 组中的上游服务器来解析域名
- set upstream name to *name*  
  使用名称为 *name* 的上游服务器来解析域名
- replace domain by *domain*  
  将请求中的域名替换为 *domain*
- set proxy on  
  启用代理服务器访问上游服务器（须在配置文件中设置 proxy 项）
- set proxy off  
  禁用代理服务器访问上游服务器
- set proxy to *proxy*  
  指定代理服务器访问上游服务器。*proxy* 格式如 http://127.0.0.1:8080 或 socks5://127.0.0.1:1080 

### 3.4 after 语句

- block if *expr1*  
  当解析结果满足条件（ *expr1* 表达式为真）时，屏蔽域名
- return *ip* if *expr1*  
  当解析结果满足条件（ *expr1* 表达式为真）时，用 *ip* 替代解析结果
- return (*ip1*, *ip2*, ...) if *expr1*
- append record *ip*  
  在上游服务器返回的解析结果后追加记录
- append record (*ip1*, *ip2*, ...)
- append record *ip* if *expr1*
- append record (*ip1*, *ip2*, ...) if *expr1*
- insert record *ip*  
  在上游服务器返回的解析结果前插入记录
- insert record (*ip1*, *ip2*, ...)
- insert record *ip* if *expr1*
- insert record (*ip1*, *ip2*, ...) if *expr1*
- remove record where *expr2*  
  从解析结果中移除满足条件（ *expr2* 表达式为真）的记录
- replace record by *ip* where *expr2*  
  用 *ip* 替换满足条件（ *expr2* 表达式为真）的记录
- run "*command*" where *expr2*  
  当解析结果中存在满足条件的记录时，执行 *command* 命令。命令需要用半角双引号包裹，命令中可以使用 `{ip}` 占位符表示当前记录的 IP 地址。

#### 3.4.1 expr1 类型表达式

- any ip is *ip*  
  解析结果中存在 IP 地址等于 *ip* 的记录
- any ip is (*ip1*, *ip2*, ...)
- any ip is not *ip*
- any ip is not (*ip1*, *ip2*, ...)
- any ip in *cidr*  
  解析结果中存在 IP 地址在 *cidr* 范围内的记录。 *cidr* 使用 IP-CIDR 格式表示，如 192.168.1.1/24
- any ip in (*cidr1*, *cidr2*, ...)
- any ip not in *cidr*
- any ip not in (*cidr1*, *cidr2*, ...)
- any geoip is *country*  
  解析结果中存在 IP 地址所在国为 *country* 的记录
- any geoip is not *country*
- all ip is *ip*  
  解析结果中所有记录的 IP 地址都等于 *ip* 
- all ip is (*ip1*, *ip2*, ...)
- all ip is not *ip*
- all ip is not (*ip1*, *ip2*, ...)
- all ip in *cidr*  
  解析结果中所有记录的 IP 地址都在 *cidr* 范围内 
- all ip in (*cidr1*, *cidr2*, ...)
- all ip not in *cidr*
- all ip not in (*cidr1*, *cidr2*, ...)
- all geoip is *country*  
  解析结果中所有记录的 IP 所在国都为 *country*  
- all geoip is not *country*

#### 3.4.2 expr2 类型表达式

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
  第一条记录
- last  
  最后一条记录

## 4. 特性

- 如果 DNS 解析请求中包含多条查询，会被逐条拆分后发送至上游服务器，并在返回响应时重新组合。这么做的目的是为了方便中间件处理；
- 程序在引导时会优先使用 priority 值最大的 upstream 来解析 DoH 服务器的域名。默认使用 cloudflare-tls 服务器进行引导时解析；
- 程序启动时会测试配置中所有的上游服务器，并将响应最快的服务器设置为主服务器；
- 程序内置的 GeoIP2 数据库仅包含中国 IP 段数据，只能返回 `cn` 或空。要使用完整的 GeoIP2 数据库，可以在配置文件中指定数据库文件；
- 程序内置的上游 DNS 解析服务器包括：[Cloudflare DNS](https://1.1.1.1/dns/) (cloudflare), [Google Public DNS](https://developers.google.com/speed/public-dns) (google), [阿里公共DNS](https://alidns.com/) (alidns), [114DNS](https://www.114dns.com/) (114dns), [OneDNS ](https://www.onedns.net/)(onedns), [DNSPod](https://www.dnspod.cn/) (dnspod), [百度DNS](https://dudns.baidu.com/)(baidu), [OpenDNS](https://www.opendns.com/) (opendns), [AdGuard DNS](https://adguard-dns.io/) (adguard) 。这些服务器按照服务供应商的名称（见括号内）分为不同组；根据服务器所在地，分为 cn 组和 global 组；根据服务器网络类型，分为 ipv4 组和 ipv6 组。

## 5. 常用命令

模块构建打包（需要安装 build 模块）：

```shell
pip install build
python -m build
```

运行单元测试：

```shell
python -m unittest tests
```

Windows 下使用 Nuitka 生成可执行文件：

```powershell
pip install nuitka ordered-set zstandard dnspooh
nuitka --standalone --output-dir=build --output-filename=dnspooh --windows-icon-from-ico=./webui/favicon.ico --include-package-data=dnspooh --onefile main.py
```

