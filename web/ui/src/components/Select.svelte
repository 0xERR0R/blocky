<script>
  let { value = $bindable(''), options = [], disabled = false } = $props()
</script>

<select class="select" {disabled} bind:value>
  {#each options as opt}
    <option value={opt.value}>{opt.label}</option>
  {/each}
</select>

<style>
  .select {
    font-family: inherit;
    font-size: var(--text-base);
    width: 100%;
    padding: 0.5rem;
    background: var(--color-bg);
    border: 1px solid var(--color-btn-border);
    border-radius: var(--radius);
    color: var(--color-text);
    outline: none;
    transition: border-color var(--transition);
  }

  .select:focus {
    border-color: var(--color-accent);
  }

  .select:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }
</style>
