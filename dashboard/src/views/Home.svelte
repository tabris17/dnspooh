<script lang="ts">
    import PageTitle from '../components/PageTitle.svelte'
    import { get, post } from '../utils'

    let query = get('/status')

    let restartPedding = false

    function reload() {
        query = get('/status')
    }

    async function restart() {
        restartPedding = true
        await post('/restart')
        restartPedding = false
        reload()
    }

    function getStatusText(status: string): string {
        switch (status) {
            case 'INITIALIZED': return '已初始化'
            case 'START_PEDDING': return '正在启动'
            case 'RUNNING': return '正在运行'
            case 'RESTART_PEDDING': return '正在重启'
            case 'STOP_PEDDING': return '正在停止'
            case 'STOPPED': return '已停止'
        }
        return '未知'
    }

    let queryDNS: Promise<any>
    let queryGeoIP2: Promise<any>

    function resolveDomain(this: HTMLElement) {
        let input = this.parentNode.parentNode.querySelector('input[name="domain"]')
        let domain = (input as HTMLInputElement).value
        queryDNS = post('/dns-query', {domain: domain})
    }

    function resolveGeoIP2(this: HTMLElement) {
        let input = this.parentNode.parentNode.querySelector('input[name="ip"]')
        let ip = (input as HTMLInputElement).value
        queryGeoIP2 = post('/geoip2-query', {ip: ip})
    }

    setInterval(() => reload(), 5000)
</script>

<PageTitle text="Dnspooh 服务">
    <p class="subtitle" slot="left">{#await query then payload}{getStatusText(payload.result)}{/await}</p>
    <div class="buttons" slot="right">
        {#await query then payload}
        {#if payload.result == 'RUNNING'}
        <button class="button is-info is-light" class:is-loading="{restartPedding}" on:click={restart}>重启</button>
        {/if}
        {/await}
    </div>
</PageTitle>

<!-- svelte-ignore a11y-label-has-associated-control -->
<div class="columns">
    <div class="column is-half">
        <div class="card">
            <header class="card-header">
                <p class="card-header-title">域名解析</p>
            </header>
            <div class="card-content">
                <div class="field has-addons">
                    <p class="control is-expanded">
                        <input class="input" name="domain" type="text" placeholder="请输入域名">
                    </p>
                    <p class="control">
                        <button class="button is-info" on:click={resolveDomain}>解析</button>
                    </p>
                </div>
                {#if queryDNS}
                <div class="content">
                    {#await queryDNS then payload}
                    {#if payload.error}
                    <div class="notification is-warning">{payload.error.message}</div>
                    {:else}
                    <pre><code>{payload.result}</code></pre>
                    {/if}
                    {/await}
                </div>
                {/if}
            </div>
        </div>
    </div>
    <div class="column is-half">
        <div class="card">
            <header class="card-header">
                <p class="card-header-title">查询 IP 地理位置</p>
            </header>
            <div class="card-content">
                <div class="field has-addons">
                    <p class="control is-expanded">
                        <input class="input" name="ip" type="text" placeholder="请输入 IP 地址">
                    </p>
                    <p class="control">
                        <button class="button is-info" on:click={resolveGeoIP2}>解析</button>
                    </p>
                </div>
                {#if queryGeoIP2}
                <div class="content">
                    {#await queryGeoIP2 then payload}
                    {#if payload.error}
                    <div class="notification is-warning">{payload.error.message}</div>
                    {:else}
                    <pre><code>{JSON.stringify(payload.result, null, 2)}</code></pre>
                    {/if}
                    {/await}
                </div>
                {/if}
            </div>
        </div>
    </div>
</div>

<style>
</style>
