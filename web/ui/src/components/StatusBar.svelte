<script>
  let { connected = false, version = '', pendingChanges = 0 } = $props()
</script>

<footer class="status">
  <span class="dot" class:connected></span>
  <span>{connected ? 'connected' : 'disconnected'}</span>
  {#if version}
    <span class="sep">/</span>
    <span>v{version}</span>
  {/if}
  {#if pendingChanges > 0}
    <span class="pending">{pendingChanges} unsaved</span>
  {/if}
</footer>

<style>
  .status {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: 0.25rem 1rem;
    border-top: 1px dotted var(--color-border);
    font-size: var(--text-xs);
    color: var(--color-text-dim);
  }

  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--color-danger);
  }

  .dot.connected {
    background: var(--color-accent);
    box-shadow: 0 0 4px var(--color-accent);
  }

  .sep { color: var(--color-border); }

  .pending {
    margin-left: auto;
    color: var(--color-warning);
  }
</style>
