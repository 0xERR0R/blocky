<script>
  let { value = $bindable(''), type = 'text', placeholder = '', error = '', disabled = false } = $props()
</script>

<input
  class="input"
  class:has-error={error}
  {type}
  {placeholder}
  {disabled}
  bind:value
/>

<style>
  .input {
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

  .input::placeholder {
    color: var(--color-text-dim);
  }

  .input:focus {
    border-color: var(--color-accent);
  }

  .input:disabled {
    opacity: 0.4;
  }

  .input.has-error {
    border-color: var(--color-danger);
  }
</style>
