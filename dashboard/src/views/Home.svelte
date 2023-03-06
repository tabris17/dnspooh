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

    let queryResolve: Promise<any>

    function resolveDomain(this: HTMLElement) {
        let input = this.parentNode.parentNode.querySelector('input[name="domain"]')
        let domain = (input as HTMLInputElement).value
        queryResolve = post('/dns-query', {domain: domain})
    }

    setInterval(() => reload(), 5000)
</script>

<PageTitle text="Dnspooh 服务">
    <p class="subtitle" slot="left">{#await query then payload}{getStatusText(payload.status)}{/await}</p>
    <div class="buttons" slot="right">
        {#await query then payload}
        {#if payload.status == 'RUNNING'}
        <button class="button is-info is-light" class:is-loading="{restartPedding}" on:click={restart}>重启</button>
        {/if}
        {/await}
    </div>
</PageTitle>

<!-- svelte-ignore a11y-label-has-associated-control -->
<div class="columns">
    <div class="column">
        <div class="card">
            <header class="card-header">
                <p class="card-header-title">域名解析</p>
            </header>
            <div class="card-content">
                <div class="content">
                    <div class="field has-addons">
                        <p class="control is-expanded">
                            <input class="input" name="domain" type="text" placeholder="请输入域名">
                        </p>
                        <p class="control">
                            <button class="button is-info" on:click={resolveDomain}>解析</button>
                        </p>
                    </div>
                    {#await queryResolve then payload}
                    {#if payload}
                    <textarea readonly class="input">{payload.result}</textarea>
                    {/if}
                    {/await}
                </div>
            </div>
        </div>
    </div>
    <div class="column">
        <div class="card">
            <header class="card-header">
                <p class="card-header-title">地理位置解析</p>
            </header>
            <div class="card-content">
                <div class="content">
                    <div class="field has-addons">
                        <p class="control is-expanded">
                            <input class="input" type="text" placeholder="请输入 IP 地址">
                        </p>
                        <p class="control">
                            <button class="button is-info">解析</button>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<style>

</style>
