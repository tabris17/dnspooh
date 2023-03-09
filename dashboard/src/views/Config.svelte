<script lang="ts">
    import PageTitle from '../components/PageTitle.svelte'
    import { get } from '../utils'
    import ConfigItem from './Config.Item.svelte'

    let query = get('/config')
</script>

<PageTitle text="配置信息"/>

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
          <th>名称</th>
          <th>类型</th>
          <th>值</th>
          <th>描述</th>
        </tr>
    </thead>
    <tbody>
        {#each payload.result as item}
        <ConfigItem item={item}/>
        {/each}
    </tbody>
</table>
{/if}
{/await}
