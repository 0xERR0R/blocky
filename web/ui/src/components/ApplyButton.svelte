<script>
  let { pending = 0, loading = false, onclick } = $props()
</script>

{#if pending > 0}
  <div class="apply">
    <span class="apply-text">{pending} pending change{pending > 1 ? 's' : ''}</span>
    <button class="apply-btn" disabled={loading} {onclick}>
      {#if loading}
        applying...
      {:else}
        apply
      {/if}
    </button>
  </div>
{/if}

<style>
  .apply {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.5rem 1rem;
    border: 1px solid var(--color-primary);
    border-radius: var(--radius);
    background: var(--color-primary-muted);
    margin-bottom: 1rem;
  }

  .apply-text {
    font-size: var(--text-sm);
    color: var(--color-primary);
  }

  .apply-btn {
    font-family: inherit;
    font-size: var(--text-sm);
    padding: 0.35rem 1rem;
    border: 1px solid var(--color-primary);
    border-radius: var(--radius);
    background: var(--color-btn-bg);
    color: var(--color-primary);
    cursor: pointer;
    transition: background var(--transition);
  }

  .apply-btn:hover:not(:disabled) {
    background: var(--color-primary);
    color: var(--color-text-inverse);
  }

  .apply-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
