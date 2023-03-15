import App from './App.svelte';

const app = new App({
	target: document.body,
	props: {
		name: 'Dnspooh 控制台',
	}
});

export default app;
