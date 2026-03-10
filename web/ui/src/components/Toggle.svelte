<script>
  let { checked = $bindable(false), disabled = false, label = '' } = $props()
</script>

<label class="toggle" class:disabled>
  <input type="checkbox" bind:checked {disabled} />
  <span class="track">
    <span class="thumb"></span>
  </span>
  {#if label}
    <span class="toggle-label">{label}</span>
  {/if}
</label>

<style>
  .toggle {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    cursor: pointer;
  }

  .toggle.disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  input {
    position: absolute;
    opacity: 0;
    width: 0;
    height: 0;
  }

  .track {
    position: relative;
    width: 32px;
    height: 16px;
    background: var(--color-btn-border);
    border-radius: var(--radius);
    transition: background var(--transition);
  }

  input:checked + .track {
    background: var(--color-accent);
  }

  .thumb {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 12px;
    height: 12px;
    background: var(--color-bg);
    border-radius: var(--radius);
    transition: transform var(--transition);
  }

  input:checked + .track .thumb {
    transform: translateX(16px);
  }

  .toggle-label {
    font-size: var(--text-sm);
    color: var(--color-text);
  }
</style>
