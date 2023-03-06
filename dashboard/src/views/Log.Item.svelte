<script lang="ts">
    export let item: {
        id: number, 
        created_at: string,
        elapsed_time: number,
        qname: string,
        qtype: string,
        success: boolean,
        traceback?: string,
        error?: string,
    }
</script>

<tr>
    <td>{item.id}</td>
    <td>{item.created_at}</td>
    <td>{item.elapsed_time.toFixed(6)}</td>
    <td class="has-text-right">{item.qname}</td>
    <td>{item.qtype}</td>
    <td class="has-text-centered">{#if item.success}√{:else}<abbr title={item.error}>错误</abbr>{/if}</td>
    <td>{#if item.traceback}{JSON.parse(item.traceback)}{/if}</td>
</tr>
