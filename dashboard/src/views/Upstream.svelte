<script lang="ts">
    import PageTitle from '../components/PageTitle.svelte'
    import { get, post } from '../utils'

    let testAllPedding = false

    let query = get('/upstreams')

    function reload() {
        query = get('/upstreams')
    }

    async function testAll() {
        testAllPedding = true
        await post('/upstreams/test-all')
        testAllPedding = false
        reload()
    }

    function renderUpstream(upstream: any) {
        switch (upstream.type) {
            case 'dns': return `dns://${upstream.host}:${upstream.port}`
            case 'dot': return `tls://${upstream.host}:${upstream.port}`
            case 'doh': return upstream.url
        }
        return '未知'
    }

    async function handleSelectPrimaryUpstream(this: HTMLElement) {
        const name = this.dataset.name
        let result = await post('/upstreams/primary', {name: name})
        if (result) {
            return reload()
        }
        alert('请求失败')
    }

    async function handleTestUpstream(this: HTMLElement) {
        const name = this.dataset.name
        let response = await post('/upstreams/test', {name: name})
        if (response.error) {
            alert(response.error.message)
            return
        }
        alert(response.result ? '测试成功：该节点可以正常访问' : '测试失败：该节点无法正常访问')
    }
</script>

<PageTitle text={'上游节点'}>
    <p class="subtitle" slot="left">
        {#await query then payload}({payload.upstreams.length}){/await}
    </p>
    <div class="buttons" slot="right">
        <button class="button is-info is-light" class:is-loading="{testAllPedding}" on:click={testAll}>测试全部节点</button>
        <button class="button is-info is-light" on:click={reload}>刷新</button>
    </div>
</PageTitle>

<!-- svelte-ignore a11y-label-has-associated-control -->
<!-- svelte-ignore a11y-click-events-have-key-events -->
<!-- svelte-ignore a11y-missing-attribute -->
{#await query then payload}
{#if payload.error}
<article class="message">
    <div class="message-header">
      <p>错误</p>
    </div>
    <div class="message-body">{payload.error.message}</div>
</article>
{:else}
<div class="columns is-multiline is-size-7">
    {#each payload.upstreams as upstream}
    <div class="column is-one-quarter">
        <div 
            class="card" 
            class:is-primary="{payload.primary.name == upstream.name}"
            class:is-disabled="{upstream.disable}"
        >
            <div class="field">
                <header class="card-header">
                    <p class="card-header-title">{upstream.name}</p>
                </header>
                <div class="card-content">
                    <div class="content">
                        <p><label>地址：</label>{renderUpstream(upstream)}</p>
                        <p><label>速度：</label>{upstream.priority}</p>
                        <p><label>健康：</label>{upstream.health}</p>
                        {#if upstream.timeout}
                        <p><label>超时：</label>{upstream.timeout}</p>
                        {/if}
                        {#if upstream.proxy}
                        <p><label>代理：</label>{upstream.proxy}</p>
                        {/if}
                    </div>
                    {#if upstream.groups}
                    <div class="tags are-small">
                        {#each upstream.groups as group}
                        <span class="tag is-light is-link">{group}</span>
                        {/each}
                    </div>
                    {/if}
                  </div>
                  <footer class="card-footer">
                    {#if upstream.disable}
                    <p class="card-footer-item">不可用</p>
                    {:else if payload.primary.name == upstream.name}
                    <p class="card-footer-item">主节点</p>
                    {:else}
                    <a on:click={handleSelectPrimaryUpstream} class="card-footer-item" data-name="{upstream.name}">设为主节点</a>
                    {/if}
                    <a on:click={handleTestUpstream} class="card-footer-item" data-name="{upstream.name}">测试节点</a>
                </footer>
            </div>
        </div>
    </div>
    {/each}
</div>
{/if}
{/await}

<style>
    .content p>label {
        display: inline-block;
        width: 4rem;
    }

    .is-disabled {
        background-color: #f5f5f5;
    }

    .is-primary {
        background-color: #3e8ed0;
        color: white;
    }

    .is-primary .card-header-title,
    .is-primary .card-footer-item {
        color: white;
    }
</style>
