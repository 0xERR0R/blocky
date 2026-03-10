<script>
  let { open = $bindable(false), title = '', children, actions } = $props()

  function onBackdrop(e) {
    if (e.target === e.currentTarget) open = false
  }

  function onKeydown(e) {
    if (e.key === 'Escape') open = false
  }
</script>

<svelte:window onkeydown={onKeydown} />

{#if open}
  <div class="backdrop" onclick={onBackdrop} role="dialog" aria-modal="true">
    <div class="modal">
      <div class="modal-header">
        <h2 class="modal-title">{title}</h2>
        <button class="modal-close" onclick={() => open = false} aria-label="Close">x</button>
      </div>
      <div class="modal-body">
        {@render children()}
      </div>
      {#if actions}
        <div class="modal-footer">
          {@render actions()}
        </div>
      {/if}
    </div>
  </div>
{/if}

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.7);
    z-index: 100;
  }

  .modal {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    width: min(480px, 90vw);
    max-height: 85vh;
    display: flex;
    flex-direction: column;
  }

  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--color-border);
  }

  .modal-title {
    font-size: var(--text-sm);
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--color-text-muted);
  }

  .modal-close {
    background: none;
    border: none;
    color: var(--color-text-dim);
    font-size: var(--text-base);
    padding: 0;
  }

  .modal-close:hover {
    color: var(--color-text);
  }

  .modal-body {
    padding: 1.5rem;
    overflow-y: auto;
  }

  .modal-footer {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-2);
    padding: 1rem 1.5rem;
    border-top: 1px dotted var(--color-border);
  }
</style>
