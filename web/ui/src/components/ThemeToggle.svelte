<script>
  import { getTheme, toggleTheme } from '../lib/theme.svelte.js'

  let theme = $derived(getTheme())
</script>

<button class="theme-toggle" onclick={toggleTheme} title="Switch to {theme === 'light' ? 'dark' : 'light'} theme">
  {theme === 'light' ? '◐' : '◑'}
</button>

<style>
  .theme-toggle {
    background: none;
    border: 1px solid var(--color-border);
    color: var(--color-text-muted);
    font-size: var(--text-lg);
    padding: 0.15rem 0.4rem;
    border-radius: var(--radius);
    cursor: pointer;
    transition: color var(--transition), border-color var(--transition);
    line-height: 1;
  }

  .theme-toggle:hover {
    color: var(--color-text);
    border-color: var(--color-text-muted);
  }
</style>
