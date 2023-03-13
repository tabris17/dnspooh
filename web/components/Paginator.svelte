<script lang="ts">
    export let page: {
        current: number,
        count: number,
        size: number,
    };

    const paginationWidth = 5;

    let paginationPaddingLeft = Math.floor(paginationWidth / 2)

    let begin = page.current - paginationPaddingLeft
    if (begin < 1) begin = 1

    let end =  begin + paginationWidth - 1
    if (end > page.count) {
        end = page.count
        begin = end - paginationWidth + 1
        if (begin < 1) begin = 1
    }

    export let handle: () => void;

    const range = (start: number, stop: number, step: number = 1) =>
        Array.from(
            { length: (stop - start) / step + 1 },
            (value, index) => start + index * step
        );
</script>

<!-- svelte-ignore a11y-no-redundant-roles -->
<!-- svelte-ignore a11y-missing-attribute -->
<!-- svelte-ignore a11y-click-events-have-key-events -->
<nav class="pagination" role="navigation">
    {#if page.current == 1}
    <button class="pagination-previous" disabled>上一页</button>
    {:else}
    <a class="pagination-previous" on:click={handle} data-page={page.current - 1}>上一页</a>
    {/if}
    {#if page.current >= page.count}
    <button class="pagination-next" disabled>下一页</button>
    {:else}
    <a class="pagination-next" on:click={handle} data-page={page.current + 1}>下一页</a>
    {/if}
    <ul class="pagination-list">
        {#if begin > 1}
        <li><a class="pagination-link" on:click={handle} data-page={1}>1</a></li>
        {#if begin > 2}<li><span class="pagination-ellipsis">&hellip;</span></li>{/if}
        {/if}

        {#each range(begin, end) as i}
        {#if i == page.current}
        <li><a class="pagination-link is-current">{i}</a></li>
        {:else}
        <li><a class="pagination-link" on:click={handle} data-page={i}>{i}</a></li>
        {/if}
        {/each}

        {#if page.count > 0 && end < page.count}
        {#if end < page.count - 1}<li><span class="pagination-ellipsis">&hellip;</span></li>{/if}
        <li><a class="pagination-link" on:click={handle} data-page={page.count}>{page.count}</a></li>
        {/if}
    </ul>
</nav>
