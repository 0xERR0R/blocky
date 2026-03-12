<script>
  import ApplyButton from './ApplyButton.svelte'
  import ThemeToggle from './ThemeToggle.svelte'
  import { getDirtyCount, clearDirty, onDirtyChange } from '../lib/dirty.svelte.js'
  import { apply } from '../lib/api.js'

  let { currentPath = '/', children } = $props()
  let pendingCount = $state(getDirtyCount())
  let applying = $state(false)

  $effect(() => {
    return onDirtyChange((n) => { pendingCount = n })
  })

  async function handleApply() {
    applying = true
    try {
      await apply()
      clearDirty()
    } catch (e) {
      console.error('apply failed:', e)
    }
    applying = false
  }

  const nav = [
    { path: '/', label: 'dashboard' },
    { path: '/client-groups', label: 'client groups' },
    { path: '/blocklists', label: 'blocklists' },
    { path: '/custom-dns', label: 'custom dns' },
    { path: '/settings', label: 'settings' },
    { path: '/logs', label: 'logs' },
  ]
</script>

<div class="shell">
  <div class="header">
    <h1>blocky</h1>
    <nav class="nav">
      {#each nav as item}
        <a
          href="#{item.path}"
          class="nav-item"
          class:active={currentPath === item.path}
        >{item.label}</a>
      {/each}
      <ThemeToggle />
    </nav>
  </div>
  <ApplyButton pending={pendingCount} loading={applying} onclick={handleApply} />
  <main class="content">
    {@render children()}
  </main>
</div>

<style>
  .shell {
    max-width: 1100px;
    margin: 0 auto;
    padding: 2rem 1rem;
  }

  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
    border-bottom: 1px solid var(--color-border);
    padding-bottom: 0.75rem;
  }

  h1 {
    font-size: var(--text-2xl);
    font-weight: 700;
  }

  .nav {
    display: flex;
    gap: 1rem;
    font-size: var(--text-sm);
  }

  .nav-item {
    color: var(--color-text-muted);
    text-decoration: none;
    padding: 0.25rem 0;
    border-bottom: 1px dotted transparent;
    transition: color var(--transition);
  }

  .nav-item:hover {
    color: var(--color-text);
  }

  .nav-item.active {
    color: var(--color-accent);
    border-bottom-color: var(--color-accent);
  }

  .content {
    min-height: 80vh;
  }
</style>
