<script>
  let { variant = 'neutral', children } = $props()
</script>

<span class="badge badge-{variant}">
  {@render children()}
</span>

<style>
  .badge {
    font-size: var(--text-xs);
    padding: 0.1rem 0.4rem;
    border: 1px solid var(--color-btn-border);
    border-radius: var(--radius);
    white-space: nowrap;
  }

  .badge-success { color: var(--color-success); border-color: var(--color-success); }
  .badge-warning { color: var(--color-warning); border-color: var(--color-warning); }
  .badge-danger { color: var(--color-danger); border-color: var(--color-danger); }
  .badge-info { color: var(--color-info); border-color: var(--color-info); }
  .badge-neutral { color: var(--color-text-muted); border-color: var(--color-btn-border); }
</style>
