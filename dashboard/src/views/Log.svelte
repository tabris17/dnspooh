<script lang="ts">
    import PageTitle from '../components/PageTitle.svelte'
    import Paginator from '../components/Paginator.svelte'
    import { get } from '../utils'
    import LogItem from './Log.Item.svelte'

    let page: number = 1
    let query = get('/logs?page=' + page)

    function handlePagination(this: HTMLElement) {
        let page = this.dataset.page
        query = get('/logs?page=' + page)
    }
</script>

<PageTitle text="解析日志">
    <div slot="right">
        {#await query then payload}
        {#if !payload.error}<Paginator page={payload.page} handle={handlePagination}/>{/if}
        {/await}
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
<table class="table is-fullwidth">
    <thead>
        <tr>
          <th>#</th>
          <th>请求时间</th>
          <th>耗时</th>
          <th>域名</th>
          <th>类型</th>
          <th>成功</th>
          <th>跟踪</th>
          <th>错误</th>
        </tr>
    </thead>
    <tbody>
        {#each payload.logs as item}
        <LogItem item={item}/>
        {/each}
    </tbody>
</table>
{/if}
{/await}
