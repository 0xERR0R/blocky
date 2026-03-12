<script>
  import Card from '../components/Card.svelte'
  import Button from '../components/Button.svelte'
  import DataTable from '../components/DataTable.svelte'
  import Modal from '../components/Modal.svelte'
  import FormField from '../components/FormField.svelte'
  import TextInput from '../components/TextInput.svelte'
  import Toggle from '../components/Toggle.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import { blocklistSources, clientGroups } from '../lib/api.js'
  import { markDirty } from '../lib/dirty.svelte.js'

  let sources = $state([])
  let groups = $state([])
  let loading = $state(true)

  // Edit modal
  let editOpen = $state(false)
  let editId = $state(null)
  let form = $state({ group_name: '', list_type: 'deny', source_type: 'http', source: '', enabled: true })

  // Group assignment modal
  let assignOpen = $state(false)
  let assignSource = $state(null)
  let assignChecked = $state({})

  function generateGroupName(source) {
    try {
      const url = new URL(source)
      const parts = url.hostname.split('.').filter(p => p !== 'www')
      const path = url.pathname.split('/').filter(Boolean).slice(0, 2).join('-')
      const name = [...parts, path].filter(Boolean).join('-').toLowerCase()
      return name || `list-${Date.now()}`
    } catch {
      return `list-${Date.now()}`
    }
  }

  // Count how many client groups reference a given group_name
  function groupCount(groupName) {
    return groups.filter(g => g.groups?.includes(groupName)).length
  }

  const columns = [
    { key: 'source', label: 'Source' },
    { key: 'enabled', label: 'Status', render: (r) => r.enabled ? '✓' : '—' },
    { key: 'group_name', label: 'Client Groups', render: (r) => `${groupCount(r.group_name)}` },
  ]

  async function load() {
    loading = true
    try {
      ;[sources, groups] = await Promise.all([
        blocklistSources.list().then(r => r ?? []),
        clientGroups.list().then(r => r ?? []),
      ])
    } catch {
      sources = []
      groups = []
    }
    loading = false
  }

  function openNew() {
    editId = null
    form = { group_name: '', list_type: 'deny', source_type: 'http', source: '', enabled: true }
    editOpen = true
  }

  function openEdit(row) {
    editId = row.id
    form = { ...row }
    editOpen = true
  }

  async function save() {
    if (!editId) {
      form.group_name = generateGroupName(form.source)
    }
    if (editId) {
      await blocklistSources.update(editId, form)
    } else {
      await blocklistSources.create(form)
    }
    editOpen = false
    markDirty()
    await load()
  }

  async function remove(id) {
    await blocklistSources.delete(id)
    markDirty()
    await load()
  }

  // --- Group assignment modal ---
  function openAssign(row) {
    assignSource = row
    assignChecked = {}
    for (const g of groups) {
      assignChecked[g.name] = g.groups?.includes(row.group_name) ?? false
    }
    assignOpen = true
  }

  function selectAll() {
    for (const g of groups) {
      assignChecked[g.name] = true
    }
  }

  function selectNone() {
    for (const g of groups) {
      assignChecked[g.name] = false
    }
  }

  async function saveAssignments() {
    const groupName = assignSource.group_name
    const updates = []

    for (const g of groups) {
      const hasIt = g.groups?.includes(groupName) ?? false
      const wantIt = assignChecked[g.name] ?? false

      if (hasIt === wantIt) continue

      let newGroups
      if (wantIt) {
        newGroups = [...(g.groups ?? []), groupName]
      } else {
        newGroups = (g.groups ?? []).filter(n => n !== groupName)
      }
      updates.push(clientGroups.put(g.name, { clients: g.clients, groups: newGroups }))
    }

    if (updates.length > 0) {
      await Promise.all(updates)
      markDirty()
      await load()
    }
    assignOpen = false
  }

  load()
</script>

<div class="page">
  <h1 class="page-title">Blocklist Sources</h1>

  <Card>
    {#snippet actions()}
      <Button size="sm" onclick={openNew}>Add Source</Button>
    {/snippet}
    {#if loading}
      <EmptyState message="Loading..." />
    {:else if sources.length === 0}
      <EmptyState message="no blocklist sources configured">
        <Button size="sm" onclick={openNew}>Add your first source</Button>
      </EmptyState>
    {:else}
      <DataTable {columns} rows={sources}>
        {#snippet rowActions(row)}
          <Button size="sm" onclick={() => openAssign(row)}>Groups</Button>
          <Button size="sm" onclick={() => openEdit(row)}>Edit</Button>
          <Button size="sm" variant="danger" onclick={() => remove(row.id)}>Delete</Button>
        {/snippet}
      </DataTable>
    {/if}
  </Card>
</div>

<!-- Create/Edit Source Modal -->
<Modal bind:open={editOpen} title={editId ? 'Edit Source' : 'New Blocklist Source'}>
  <FormField label="Source">
    <TextInput bind:value={form.source} placeholder="https://example.com/blocklist.txt" />
  </FormField>
  <FormField label="Enabled">
    <Toggle bind:checked={form.enabled} />
  </FormField>
  {#snippet actions()}
    <Button onclick={() => editOpen = false}>Cancel</Button>
    <Button onclick={save}>Save</Button>
  {/snippet}
</Modal>

<!-- Group Assignment Modal -->
<Modal bind:open={assignOpen} title="Assign to Client Groups">
  {#if groups.length === 0}
    <p class="empty-hint">No client groups exist yet. Create one from the Client Groups page.</p>
  {:else}
    <div class="assign-actions">
      <Button size="sm" onclick={selectAll}>All</Button>
      <Button size="sm" onclick={selectNone}>None</Button>
    </div>
    <div class="assign-list">
      {#each groups as g}
        <label class="assign-row">
          <input type="checkbox" bind:checked={assignChecked[g.name]} />
          <span>{g.name}</span>
        </label>
      {/each}
    </div>
  {/if}
  {#snippet actions()}
    <Button onclick={() => assignOpen = false}>Cancel</Button>
    {#if groups.length > 0}
      <Button onclick={saveAssignments}>Save</Button>
    {/if}
  {/snippet}
</Modal>

<style>
  .page { max-width: 1000px; }
  .page-title {
    font-size: var(--text-2xl);
    font-weight: 700;
    margin-bottom: var(--space-6);
  }

  .empty-hint {
    color: var(--color-text-dim);
    font-size: var(--text-sm);
    font-style: italic;
  }

  .assign-actions {
    display: flex;
    gap: 0.4rem;
    margin-bottom: 0.75rem;
  }

  .assign-list {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .assign-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.3rem 0.2rem;
    font-size: var(--text-sm);
    cursor: pointer;
    border-radius: var(--radius);
  }

  .assign-row:hover {
    background: var(--color-btn-bg);
  }

  .assign-row input[type="checkbox"] {
    accent-color: var(--color-accent, currentColor);
  }
</style>
