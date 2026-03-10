<script>
  let { title = '', loading = false, actions, children } = $props()
</script>

<div class="box" class:loading>
  {#if title || actions}
    <div class="box-header">
      {#if title}
        <h2 class="box-title">{title}</h2>
      {/if}
      {#if actions}
        <div class="box-actions">
          {@render actions()}
        </div>
      {/if}
    </div>
  {/if}
  <div class="box-body">
    {@render children()}
  </div>
</div>

<style>
  .box {
    border: 1px solid var(--color-border);
    background: var(--color-surface);
    border-radius: var(--radius);
    margin-bottom: 1rem;
    transition: background 0.2s, border-color 0.2s;
  }

  .box.loading {
    opacity: 0.5;
    pointer-events: none;
  }

  .box-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.75rem 1.5rem;
    border-bottom: 1px dotted var(--color-border);
  }

  .box-title {
    font-size: var(--text-sm);
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--color-text-muted);
  }

  .box-actions {
    display: flex;
    gap: var(--space-2);
  }

  .box-body {
    padding: 1.5rem;
  }
</style>
