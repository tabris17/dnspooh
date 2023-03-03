<script lang="ts">
    import PageTitle from '../components/PageTitle.svelte'
    import { get } from '../utils'

    let query = get('/logs?page=1')
</script>

<PageTitle text="解析日志"/>

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
        {#each payload.logs as log}
        <tr>
          <td>{log.id}</td>
          <td>{log.created_at}</td>
          <td>{log.elapsed_time}</td>
          <td>{log.qname}</td>
          <td>{log.qtype}</td>
          <td>{log.success}</td>
          <td>{log.traceback}</td>
          <td>{log.error}</td>
        </tr>
        {/each}
    </tbody>
</table>
{/if}
{/await}
