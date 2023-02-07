# Dnspooh 配置文件

此文件夹内的配置文件说明。

## 1. config.yml

将该配置文件放在 Dnspooh 的运行目录下，程序启动时会自动加载。

## 2. cn-domain.yml

自定义规则配置文件，是 config.yml 的一部分。配置文件中包含国内网站的域名列表，当解析其中的域名时，Dnspooh 将选择国内的 DNS 服务器。

域名列表数据来源是开源项目 [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list) 的 [accelerated-domains.china.conf](https://github.com/felixonmars/dnsmasq-china-list/blob/master/accelerated-domains.china.conf) 文件。

## 3. block.txt

域名和 IP 地址黑名单。如果查询的域名或解析结果的 IP 地址在黑名单中，则返回 NXDOMAIN （域名不存在）解析结果。

黑名单域名数据来源是开源项目 [anti-AD](https://github.com/privacy-protection-tools/anti-AD) 和 [clash-rules](https://github.com/Loyalsoldier/clash-rules) 。

黑名单 IP 地址数据来源是开源项目 [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list) 的 [bogus-nxdomain.china.conf](https://github.com/felixonmars/dnsmasq-china-list/blob/master/bogus-nxdomain.china.conf) 文件。

## 4. hosts

用于设置自定义域名解析结果。格式和系统的 hosts 文件一致，相同的域名如果存在多行记录则解析结果也会返回多条记录。

## 5. access.log

启用 log 中间件时，运行程序后会在当前目录下生成该文件，其中保存了所有的 DNS 查询记录。文件为 SQLite3 数据库格式，可以用 [SQLiteStudio](https://sqlitestudio.pl/) 、 [DB Browser for SQLite](https://sqlitebrowser.org/) 等软件打开。

----

此外，程序在启动时会从远程加载 https://raw.hellogithub.com/hosts 。该文件中提供了 Github 域名可用的 IP 解析，由开源项目 [GitHub520](https://github.com/521xueweihan/GitHub520) 提供。