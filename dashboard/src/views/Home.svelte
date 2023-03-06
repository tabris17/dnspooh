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
        return ''
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

<style>

</style>
