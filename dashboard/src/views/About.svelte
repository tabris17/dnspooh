<script lang="ts">
    import PageTitle from '../components/PageTitle.svelte'
    import { get } from '../utils'
</script>

<PageTitle text={'关于'}/>

<div class="card">
    <div class="card-content">
        <div class="media">
            <div class="media-left">
                <figure class="image is-64x64">
                    <img src="/icon.png" alt="">
                </figure>
            </div>
            <div class="media-content">
                <p class="title is-4">Dnspooh</p>
                {#await get('/version') then payload}
                <p class="subtitle is-6">版本 {payload.result}</p>
                {/await}
            </div>
        </div>

        <div class="content">
            <p>轻量级 DNS 中间人代理，支持 DoH、DoT 协议，适用于本地网络</p>
            <p>项目主页：<a href="https://github.com/tabris17/dnspooh">https://github.com/tabris17/dnspooh</a></p>
        </div>
    </div>
</div>


<style>
</style>
