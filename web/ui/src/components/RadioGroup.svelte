<script>
  let { name, options = [], value = $bindable(''), disabled = false } = $props()
</script>

<div class="radio-group">
  {#each options as opt}
    <label class="radio" class:disabled>
      <input type="radio" {name} value={opt.value} bind:group={value} {disabled} />
      <span class="radio-mark"></span>
      {opt.label}
    </label>
  {/each}
</div>

<style>
  .radio-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .radio {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
    font-size: var(--text-sm);
    color: var(--color-text);
  }

  .radio.disabled { opacity: 0.4; cursor: not-allowed; }

  input {
    position: absolute;
    opacity: 0;
    pointer-events: none;
  }

  .radio-mark {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 14px;
    height: 14px;
    border: 1px solid var(--color-btn-border);
    border-radius: 50%;
    position: relative;
    flex-shrink: 0;
    transition: border-color var(--transition);
  }

  input:checked + .radio-mark { border-color: var(--color-accent); }

  input:checked + .radio-mark::after {
    content: '';
    position: absolute;
    width: 6px;
    height: 6px;
    background: var(--color-accent);
    border-radius: 50%;
  }
</style>
