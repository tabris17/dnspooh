<script lang="ts">
    import PageTitle from '../components/PageTitle.svelte'
    import { get } from '../utils'

    let query = get('/pool')

    function reload() {
        query = get('/pool')
    }

</script>

<PageTitle text={'连接池'}>
    <div class="buttons" slot="right">
        <button class="button is-info is-light" on:click={reload}>刷新</button>
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
          <th>地址</th>
          <th>连接数</th>
        </tr>
    </thead>
    <tbody>
        {#each payload.result as conn}
        <tr>
            <td>{conn.name}</td>
            <td>{conn.size}</td>
        </tr>
        {/each}
    </tbody>
</table>
{/if}
{/await}
