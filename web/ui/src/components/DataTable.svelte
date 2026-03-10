<script>
  let { columns = [], rows = [], sortKey = '', sortDir = 'asc', onsort, rowActions } = $props()

  function handleSort(key) {
    if (!onsort) return
    if (sortKey === key) {
      onsort(key, sortDir === 'asc' ? 'desc' : 'asc')
    } else {
      onsort(key, 'asc')
    }
  }
</script>

<table>
  <thead>
    <tr>
      {#each columns as col}
        <th
          class:sortable={col.sortable}
          onclick={() => col.sortable && handleSort(col.key)}
        >
          {col.label}
          {#if col.sortable && sortKey === col.key}
            <span class="sort-arrow">{sortDir === 'asc' ? '▲' : '▼'}</span>
          {/if}
        </th>
      {/each}
      {#if rowActions}
        <th></th>
      {/if}
    </tr>
  </thead>
  <tbody>
    {#each rows as row}
      <tr>
        {#each columns as col}
          <td>{col.render ? col.render(row) : row[col.key] ?? ''}</td>
        {/each}
        {#if rowActions}
          <td class="actions">
            {@render rowActions(row)}
          </td>
        {/if}
      </tr>
    {:else}
      <tr>
        <td class="empty" colspan={columns.length + (rowActions ? 1 : 0)}>
          no data
        </td>
      </tr>
    {/each}
  </tbody>
</table>

<style>
  table {
    width: 100%;
    font-size: var(--text-sm);
    border-collapse: collapse;
  }

  th {
    text-align: left;
    color: var(--color-text-dim);
    font-weight: 400;
    padding: 0.25rem 0.75rem 0.25rem 0;
    border-bottom: 1px solid var(--color-border);
  }

  th.sortable {
    cursor: pointer;
    user-select: none;
  }

  th.sortable:hover {
    color: var(--color-text);
  }

  .sort-arrow {
    font-size: 0.6rem;
    margin-left: 0.25rem;
  }

  td {
    padding: 0.35rem 0.75rem 0.35rem 0;
    border-bottom: 1px dotted var(--color-border-subtle);
  }

  .actions {
    text-align: right;
    white-space: nowrap;
  }

  .empty {
    color: var(--color-text-dim);
    font-style: italic;
    text-align: center;
    padding: 2rem 0;
  }
</style>
