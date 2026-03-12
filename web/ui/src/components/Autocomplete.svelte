<script>
  let { suggestions = [], placeholder = '', onadd } = $props()
  let query = $state('')
  let open = $state(false)
  let selectedIndex = $state(-1)
  let inputEl

  let filtered = $derived(
    query.length > 0
      ? suggestions.filter(s => {
          const q = query.toLowerCase()
          return s.ip?.toLowerCase().includes(q)
            || s.mac?.toLowerCase().includes(q)
            || s.hostname?.toLowerCase().includes(q)
        })
      : suggestions
  )

  function select(item) {
    onadd?.(item.ip)
    query = ''
    open = false
    selectedIndex = -1
  }

  function handleKeydown(e) {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      open = true
      selectedIndex = Math.min(selectedIndex + 1, filtered.length - 1)
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      selectedIndex = Math.max(selectedIndex - 1, -1)
    } else if (e.key === 'Enter') {
      e.preventDefault()
      if (selectedIndex >= 0 && filtered[selectedIndex]) {
        select(filtered[selectedIndex])
      } else if (query.trim()) {
        onadd?.(query.trim())
        query = ''
        open = false
      }
    } else if (e.key === 'Escape') {
      open = false
      selectedIndex = -1
    }
  }

  function handleInput() {
    open = true
    selectedIndex = -1
  }

  function handleFocus() {
    if (suggestions.length > 0) open = true
  }

  function handleBlur() {
    // delay to allow click events on dropdown items
    setTimeout(() => { open = false }, 150)
  }
</script>

<div class="autocomplete">
  <input
    class="input"
    bind:this={inputEl}
    bind:value={query}
    {placeholder}
    oninput={handleInput}
    onfocus={handleFocus}
    onblur={handleBlur}
    onkeydown={handleKeydown}
  />
  {#if open && filtered.length > 0}
    <div class="dropdown">
      {#each filtered as item, i}
        <button
          class="dropdown-item"
          class:selected={i === selectedIndex}
          onmousedown={() => select(item)}
        >
          <span class="item-ip">{item.ip}</span>
          {#if item.mac}
            <span class="item-mac">{item.mac}</span>
          {/if}
          {#if item.hostname}
            <span class="item-host">{item.hostname}</span>
          {/if}
        </button>
      {/each}
    </div>
  {/if}
</div>

<style>
  .autocomplete {
    position: relative;
  }

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

  .input::placeholder { color: var(--color-text-dim); }
  .input:focus { border-color: var(--color-accent); }

  .dropdown {
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    margin-top: 2px;
    max-height: 200px;
    overflow-y: auto;
    z-index: 50;
  }

  .dropdown-item {
    display: flex;
    gap: 0.75rem;
    width: 100%;
    padding: 0.4rem 0.5rem;
    border: none;
    background: none;
    color: var(--color-text);
    font-family: inherit;
    font-size: var(--text-sm);
    text-align: left;
    cursor: pointer;
  }

  .dropdown-item:hover, .dropdown-item.selected {
    background: var(--color-btn-bg-hover);
  }

  .item-ip { font-weight: 600; min-width: 8em; }
  .item-mac { color: var(--color-text-dim); font-family: var(--font-mono); font-size: var(--text-xs); }
  .item-host { color: var(--color-text-muted); font-size: var(--text-xs); }
</style>
