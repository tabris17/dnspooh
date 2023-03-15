<script lang="ts">
    import "bulma/css/bulma.min.css"
    import Router from 'svelte-spa-router'
	import { link } from 'svelte-spa-router'
    import routes from './routes';

	export let name: string

	function toggleNavbar(this: HTMLElement) {
		this.classList.toggle('is-active')
		document.getElementById(this.dataset.target).classList.toggle('is-active')
	}
</script>


<!-- svelte-ignore a11y-no-redundant-roles -->
<!-- svelte-ignore a11y-missing-attribute -->
<!-- svelte-ignore a11y-click-events-have-key-events -->
<nav class="navbar" role="navigation" aria-label="main navigation">
    <div class="container">
        <div class="navbar-brand">
            <a class="navbar-item" use:link={'/'}>{name}</a>
            <a role="button" class="navbar-burger" aria-label="menu" aria-expanded="false" data-target="navbar" on:click={toggleNavbar}>
                <span aria-hidden="true"></span>
                <span aria-hidden="true"></span>
                <span aria-hidden="true"></span>
            </a>
        </div>
		<div id="navbar" class="navbar-menu">
			<div class="navbar-start">
				<a use:link={'/upstream'} class="navbar-item">上游节点</a>
				<a use:link={'/log'} class="navbar-item">解析日志</a>
				<a use:link={'/pool'} class="navbar-item">连接池</a>
				<a use:link={'/config'} class="navbar-item">配置信息</a>
				<a use:link={'/about'} class="navbar-item">关于</a>
			</div>
			<div class="navbar-end"></div>
		</div>
    </div>
</nav>

<main class="section">
    <div class="container">
		<Router {routes} />
	</div>
</main>

<style>
</style>
