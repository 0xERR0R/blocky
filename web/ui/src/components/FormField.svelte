<script>
  let { label = '', error = '', disabled = false, children } = $props()
</script>

<div class="field" class:disabled>
  {#if label}
    <label class="label">{label}</label>
  {/if}
  {@render children()}
  {#if error}
    <p class="error">{error}</p>
  {/if}
</div>

<style>
  .field {
    margin-bottom: 1rem;
  }

  .label {
    display: block;
    font-size: 0.85rem;
    color: var(--color-text-muted);
    margin-bottom: 0.25rem;
  }

  .error {
    font-size: var(--text-xs);
    color: var(--color-danger);
    margin-top: 0.25rem;
  }

  .disabled {
    opacity: 0.4;
    pointer-events: none;
  }
</style>
