import Home from './views/Home.svelte';
import About from './views/About.svelte';
import Upstream from './views/Upstream.svelte';
import Pool from './views/Pool.svelte';
import Config from './views/Config.svelte';
import Log from './views/Log.svelte';

const routes = {
  '/': Home,
  '/about': About,
  '/upstream': Upstream,
  '/pool': Pool,
  '/config': Config,
  '/log': Log,
}

export default routes;
