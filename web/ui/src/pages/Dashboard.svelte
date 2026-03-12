<script>
  import { onDestroy } from 'svelte'
  import Card from '../components/Card.svelte'
  import Badge from '../components/Badge.svelte'
  import { getStats } from '../lib/api.js'

  let stats = $state(null)

  async function refresh() {
    try {
      stats = await getStats()
    } catch { /* ignore */ }
  }

  refresh()
  const timer = setInterval(refresh, 5000)
  onDestroy(() => clearInterval(timer))

  function fmt(n) {
    if (n == null) return '—'
    return n.toLocaleString('en-US', { maximumFractionDigits: 0 })
  }
</script>

<div class="page">
  <h1 class="page-title">Dashboard</h1>

  <div class="stats">
    <Card>
      <div class="stat">
        <span class="stat-label">Status</span>
        <Badge variant="success">Running</Badge>
      </div>
    </Card>
    <Card>
      <div class="stat">
        <span class="stat-label">Queries</span>
        <span class="stat-value">{fmt(stats?.total_queries)}</span>
      </div>
    </Card>
    <Card>
      <div class="stat">
        <span class="stat-label">Blocked</span>
        <span class="stat-value">{fmt(stats?.blocked_queries)}</span>
      </div>
    </Card>
    <Card>
      <div class="stat">
        <span class="stat-label">Block Rate</span>
        <span class="stat-value">{stats ? stats.block_rate.toFixed(1) + '%' : '—'}</span>
      </div>
    </Card>
  </div>
</div>

<style>
  .page { max-width: 1000px; }

  .page-title {
    font-size: var(--text-2xl);
    font-weight: 700;
    margin-bottom: var(--space-6);
  }

  .stats {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: var(--space-4);
  }

  .stat {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .stat-label {
    font-size: var(--text-xs);
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .stat-value {
    font-size: var(--text-xl);
    font-weight: 600;
  }
</style>
