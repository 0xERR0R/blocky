<script>
  let { message = 'no data', children } = $props()
</script>

<div class="empty">
  <p class="empty-msg">{message}</p>
  {#if children}
    <div class="empty-action">
      {@render children()}
    </div>
  {/if}
</div>

<style>
  .empty {
    text-align: center;
    padding: 2rem 1rem;
    color: var(--color-text-dim);
    font-style: italic;
    font-size: var(--text-sm);
  }

  .empty-msg {
    margin-bottom: var(--space-3);
  }
</style>
