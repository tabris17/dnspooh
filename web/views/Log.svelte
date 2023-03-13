<script lang="ts">
    import PageTitle from '../components/PageTitle.svelte'
    import Paginator from '../components/Paginator.svelte'
    import { get, post, QTYPE } from '../utils'
    import LogItem from './Log.Item.svelte'

    let page: number = 1

    let filter: {qname?: string, qtype?: string} = {}

    let query = makeQuery()

    function reload() {
        page = 1
        filter = {}
        query = makeQuery()
    }

    function makeQuery() {
        let params = new URLSearchParams({ page: page.toString() })
        if (filter.qname) {
            params.append('qname', filter.qname)
        }
        if (filter.qtype) {
            params.append('qtype', filter.qtype)
        }
        return get('/logs?' + params.toString())
    }

    function handlePagination(this: HTMLElement) {
        page = parseInt(this.dataset.page)
        query = makeQuery()
    }

    let clearPedding = false

    async function handleClear(this: HTMLElement) {
        if (!confirm('清空操作将从数据库中删除所有记录，记录清空后无法恢复。\r是否要继续？')) {
            return
        }
        clearPedding = true
        await post('/logs/clear')
        clearPedding = false
        reload()
    }

    function handleFilter(this: HTMLElement) {
        let form = this.parentNode.parentNode
        let select: HTMLSelectElement = form.querySelector('select[name="qtype"]')
        let input: HTMLInputElement = form.querySelector('input[name="qname"]')
        let qname = input.value
        let qtype = select.options[select.selectedIndex].value
        filter = {qname: qname, qtype: qtype}
        page = 1
        query = makeQuery()
    }
</script>

<PageTitle text="解析日志">
    <div slot="right" class="field is-horizontal">
        <div class="field-body">
            <div class="field has-addons">
                <div class="control">
                    <span class="select">
                        <select name="qtype">
                            <option value="">所有类型</option>
                            {#each QTYPE as qtype}
                            <option>{qtype}</option>
                            {/each}
                        </select>
                    </span>
                </div>
                <div class="control">
                    <input class="input" name="qname" type="text" placeholder="域名关键字">
                </div>
                <div class="control">
                    <button class="button is-info" on:click={handleFilter}>查找</button>
                </div>
            </div>
            <div class="field">
                <button class="button is-danger" class:is-loading="{clearPedding}" on:click={handleClear}>清空</button>
            </div>
        </div>
    </div>
</PageTitle>

{#await query then payload}
{#if payload.error}
<article class="message">
    <div class="message-header">
      <p>错误</p>
    </div>
    <div class="message-body">{payload.error.message}</div>
</article>
{:else}
<Paginator page={payload.result.page} handle={handlePagination}/>
<table class="table is-fullwidth">
    <thead>
        <tr>
          <th>#</th>
          <th>请求时间</th>
          <th>耗时（秒）</th>
          <th>域名</th>
          <th>类型</th>
          <th>成功</th>
          <th>跟踪</th>
        </tr>
    </thead>
    <tbody>
        {#each payload.result.logs as item}
        <LogItem item={item}/>
        {:else}
        <tr><td colspan="7" class="has-text-centered">（没有数据）</td></tr>
        {/each}
    </tbody>
</table>
<Paginator page={payload.result.page} handle={handlePagination}/>
{/if}
{/await}
