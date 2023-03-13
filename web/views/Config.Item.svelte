<script lang="ts">
    export let item: { name: string, value: any }

    function formatValue(name: string, value: any)
    {
        switch (name) {
            case 'upstreams':
                return `<${value.name}>`
            case 'rules':
                return `<if: ${value.if.length > 36 ? value.if.substr(0, 36) + ' ... ': value.if}>`
            case 'listen':
                return value[0] + ':' + value[1];
        }
        return value
    }

    function getTypeAndDescription(name: string): [string, string] {
        switch (name) {
            case 'debug': return ['bool', '在终端输出调试信息']
            case 'secure': return ['bool', '仅使用 DoT/DoH 类型的上游服务器']
            case 'ipv6': return ['bool', '启用 IPv6 地址的上游服务器']
            case 'listen': return ['string | string[]', '本地 DNS 服务绑定本机网络地址和端口']
            case 'output': return ['string', '保存端输出信息的文件名']
            case 'geoip': return ['string', 'GeoIP2 数据库文件路径']
            case 'proxy': return ['string', '访问外部网络使用的代理服务器地址']
            case 'block': return ['string[]', '黑名单文件列表']
            case 'hosts': return ['string[]', 'hosts 文件列表']
            case 'rules': return ['object[]', '规则列表']
            case 'http.root': return ['string', 'HTTP 服务静态文件根路径']
            case 'http.host': return ['string', 'HTTP 服务绑定本机地址']
            case 'http.port': return ['int', 'HTTP 服务绑定本机端口']
            case 'http.timeout': return ['int', 'HTTP 服务访问超时时间（单位：毫秒）']
            case 'http.disable': return ['bool', '禁用 HTTP 服务']
            case 'middlewares': return ['string[]', '启用的中间件名称列表']
            case 'timeout': return ['int', '上游 DNS 服务器响应超时时间（单位：毫秒）']
            case 'upstreams': return ['object[]', '上游 DNS 服务器列表']
            case 'cache.max_size': return ['int', '最大缓存条目数']
            case 'cache.ttl': return ['int', '缓存有效期（单位：秒）']
            case 'log.path': return ['string', '访问日志数据库文件路径']
            case 'log.trace': return ['bool', '记录调试跟踪信息']
            case 'log.payload': return ['bool', '记录 DNS 请求和响应的数据']
        }
        return ['', '']
    }
    let [valueType, description] = getTypeAndDescription(item.name)
</script>

<tr>
    <td>{item.name}</td>
    <td>{valueType}</td>
    {#if Array.isArray(item.value)}
    <td>
    {#each item.value as value}
        {formatValue(item.name, value)}<br>
    {/each}
    </td>
    {:else}
    <td>{formatValue(item.name, item.value)}</td>
    {/if}
    <td>{description}</td>
</tr>
