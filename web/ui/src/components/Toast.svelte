<script>
  let { variant = 'info', visible = $bindable(false), duration = 4000, children } = $props()

  $effect(() => {
    if (visible && duration > 0) {
      const timer = setTimeout(() => { visible = false }, duration)
      return () => clearTimeout(timer)
    }
  })
</script>

{#if visible}
  <div class="toast toast-{variant}" role="alert">
    <span class="toast-msg">{@render children()}</span>
    <button class="toast-close" onclick={() => visible = false}>x</button>
  </div>
{/if}

<style>
  .toast {
    position: fixed;
    bottom: 1.5rem;
    right: 1.5rem;
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: 0.5rem 1rem;
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    background: var(--color-surface);
    font-size: var(--text-sm);
    z-index: 200;
    animation: slideIn var(--transition-slow) ease;
  }

  .toast-success { border-color: var(--color-success); color: var(--color-success); }
  .toast-danger { border-color: var(--color-danger); color: var(--color-danger); }
  .toast-info { border-color: var(--color-info); color: var(--color-info); }

  .toast-close {
    background: none;
    border: none;
    color: var(--color-text-dim);
    font-size: var(--text-base);
    padding: 0;
  }

  .toast-close:hover { color: var(--color-text); }

  @keyframes slideIn {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
</style>
