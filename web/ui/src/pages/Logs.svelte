<script>
  import LogViewer from '../components/LogViewer.svelte'
  import { connectLogStream } from '../lib/ws.js'
  import { onMount } from 'svelte'

  let entries = $state([])
  let connected = $state(false)

  onMount(() => {
    const disconnect = connectLogStream(
      (entry) => { entries = [...entries, entry] },
      (status) => { connected = status },
    )
    return disconnect
  })
</script>

<div class="page">
  <h1 class="page-title">Live Logs</h1>
  <div class="log-wrap">
    <LogViewer {entries} {connected} />
  </div>
</div>

<style>
  .page {
    max-width: 1200px;
    display: flex;
    flex-direction: column;
    height: calc(100vh - var(--space-8) * 2);
  }
  .page-title {
    font-size: var(--text-2xl);
    font-weight: 700;
    margin-bottom: var(--space-6);
    flex-shrink: 0;
  }
  .log-wrap {
    flex: 1;
    min-height: 0;
  }
</style>
