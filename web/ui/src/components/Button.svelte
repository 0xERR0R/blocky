<script>
  let { variant = 'default', size = 'md', loading = false, disabled = false, onclick, children } = $props()
</script>

<button
  class="btn btn-{variant} btn-{size}"
  disabled={disabled || loading}
  {onclick}
>
  {#if loading}
    <span class="spinner"></span>
  {/if}
  {@render children()}
</button>

<style>
  .btn {
    font-family: inherit;
    font-size: var(--text-base);
    border: 1px solid var(--color-btn-border);
    background: var(--color-btn-bg);
    color: var(--color-text);
    padding: 0.5rem 1.5rem;
    cursor: pointer;
    border-radius: var(--radius);
    transition: background var(--transition), border-color var(--transition);
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    white-space: nowrap;
  }

  .btn:hover:not(:disabled) {
    background: var(--color-btn-bg-hover);
  }

  .btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .btn-sm { font-size: var(--text-xs); padding: 0.2rem 0.5rem; }
  .btn-md { padding: 0.5rem 1.5rem; }
  .btn-lg { font-size: var(--text-lg); padding: 0.75rem 2rem; text-transform: uppercase; letter-spacing: 0.05em; }

  .btn-primary {
    color: var(--color-primary);
    border-color: var(--color-primary);
  }
  .btn-primary:hover:not(:disabled) {
    background: var(--color-primary);
    color: var(--color-primary-fg);
  }

  .btn-accent {
    color: var(--color-success);
    border-color: var(--color-success);
  }
  .btn-accent:hover:not(:disabled) {
    background: var(--color-success);
    color: var(--color-success-fg);
  }

  .btn-danger {
    color: var(--color-danger);
    border-color: var(--color-danger);
  }
  .btn-danger:hover:not(:disabled) {
    background: var(--color-danger);
    color: var(--color-danger-fg);
  }

  .btn-ghost {
    background: transparent;
    border-color: transparent;
    color: var(--color-text-muted);
  }
  .btn-ghost:hover:not(:disabled) {
    color: var(--color-text);
    background: transparent;
  }

  .spinner {
    width: 12px;
    height: 12px;
    border: 1px solid currentColor;
    border-right-color: transparent;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>
