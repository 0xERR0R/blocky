<script>
  import Shell from './components/Shell.svelte'
  import Dashboard from './pages/Dashboard.svelte'
  import ClientGroups from './pages/ClientGroups.svelte'
  import Blocklists from './pages/Blocklists.svelte'
  import CustomDNS from './pages/CustomDNS.svelte'
  import BlockSettings from './pages/BlockSettings.svelte'
  import Logs from './pages/Logs.svelte'
  import DevComponents from './pages/DevComponents.svelte'

  let currentPath = $state(location.hash.slice(1) || '/')

  // Hash-based routing
  $effect(() => {
    function onHash() {
      currentPath = location.hash.slice(1) || '/'
    }
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  })

  const routes = {
    '/': Dashboard,
    '/client-groups': ClientGroups,
    '/blocklists': Blocklists,
    '/custom-dns': CustomDNS,
    '/settings': BlockSettings,
    '/logs': Logs,
    '/dev': DevComponents,
  }

  let Page = $derived(routes[currentPath] || Dashboard)
</script>

<Shell {currentPath}>
  <Page />
</Shell>
