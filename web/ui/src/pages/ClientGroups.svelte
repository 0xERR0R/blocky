<script>
  import Card from '../components/Card.svelte'
  import Button from '../components/Button.svelte'
  import DataTable from '../components/DataTable.svelte'
  import Modal from '../components/Modal.svelte'
  import FormField from '../components/FormField.svelte'
  import TextInput from '../components/TextInput.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import Autocomplete from '../components/Autocomplete.svelte'
  import { clientGroups, getDiscoveredClients } from '../lib/api.js'
  import { markDirty } from '../lib/dirty.svelte.js'

  // --- State ---
  let groups = $state([])
  let loading = $state(true)

  // Detail view
  let selected = $state(null)
  let detailLoading = $state(false)

  // Create modal
  let createOpen = $state(false)
  let createName = $state('')

  // Discovered clients from ARP
  let discovered = $state([])

  // --- List view ---
  const columns = [
    { key: 'name', label: 'Name', sortable: true },
    { key: 'clients', label: 'Clients', render: (r) => `${r.clients?.length || 0}` },
    { key: 'groups', label: 'Blocklist Groups', render: (r) => `${r.groups?.length || 0}` },
  ]

  async function load() {
    loading = true
    try { groups = await clientGroups.list() ?? [] } catch { groups = [] }
    loading = false
  }

  // --- Create group (name only) ---
  function openCreate() {
    createName = ''
    createOpen = true
  }

  async function create() {
    if (!createName.trim()) return
    await clientGroups.put(createName.trim(), {})
    createOpen = false
    markDirty()
    await load()
  }

  async function remove(name) {
    await clientGroups.delete(name)
    markDirty()
    if (selected?.name === name) selected = null
    await load()
  }

  // --- Detail view ---
  async function openDetail(row) {
    detailLoading = true
    selected = row

    discovered = await getDiscoveredClients().catch(() => []) ?? []

    detailLoading = false
  }

  function backToList() {
    selected = null
  }

  // --- Client management ---
  async function addClient(value) {
    if (!value || !selected) return
    if (selected.clients.includes(value)) return

    const updated = { clients: [...selected.clients, value], groups: selected.groups }
    await clientGroups.put(selected.name, updated)
    selected = { ...selected, clients: updated.clients }
    markDirty()
    load()
  }

  async function removeClient(client) {
    if (!selected) return
    const updated = { clients: selected.clients.filter(c => c !== client), groups: selected.groups }
    await clientGroups.put(selected.name, updated)
    selected = { ...selected, clients: updated.clients }
    markDirty()
    load()
  }

  load()
</script>

<div class="page">
  {#if selected}
    <!-- DETAIL VIEW -->
    <div class="detail-header">
      <button class="back-btn" onclick={backToList}>&larr; back</button>
      <h1 class="page-title">{selected.name}</h1>
    </div>

    {#if detailLoading}
      <EmptyState message="Loading..." />
    {:else}
      <!-- Clients Card -->
      <Card title="Clients">
        <div class="chip-list">
          {#each selected.clients as client}
            <span class="chip">
              {client}
              <button class="chip-remove" onclick={() => removeClient(client)}>&times;</button>
            </span>
          {:else}
            <span class="empty-hint">no clients added yet</span>
          {/each}
        </div>
        <div class="add-section">
          <Autocomplete
            suggestions={discovered}
            placeholder="type IP, CIDR, or hostname — autocomplete from network"
            onadd={addClient}
          />
          {#if discovered.length > 0}
            <p class="hint">{discovered.length} device{discovered.length === 1 ? '' : 's'} discovered on network</p>
          {/if}
        </div>
      </Card>

    {/if}
  {:else}
    <!-- LIST VIEW -->
    <h1 class="page-title">Client Groups</h1>

    <Card>
      {#snippet actions()}
        <Button size="sm" onclick={openCreate}>Add Group</Button>
      {/snippet}
      {#if loading}
        <EmptyState message="Loading..." />
      {:else if groups.length === 0}
        <EmptyState message="no client groups configured">
          <Button size="sm" onclick={openCreate}>Create your first group</Button>
        </EmptyState>
      {:else}
        <DataTable {columns} rows={groups}>
          {#snippet rowActions(row)}
            <Button size="sm" onclick={() => openDetail(row)}>Manage</Button>
            {#if row.name !== 'default'}
              <Button size="sm" variant="danger" onclick={() => remove(row.name)}>Delete</Button>
            {/if}
          {/snippet}
        </DataTable>
      {/if}
    </Card>
  {/if}
</div>

<!-- Create Group Modal (name only) -->
<Modal bind:open={createOpen} title="New Client Group">
  <FormField label="Name">
    <TextInput bind:value={createName} placeholder="e.g. kids" />
  </FormField>
  <p class="modal-hint">You can add clients after creating the group.</p>
  {#snippet actions()}
    <Button onclick={() => createOpen = false}>Cancel</Button>
    <Button onclick={create} disabled={!createName.trim()}>Create</Button>
  {/snippet}
</Modal>

<style>
  .page { max-width: 1000px; }
  .page-title {
    font-size: var(--text-2xl);
    font-weight: 700;
    margin-bottom: var(--space-6);
  }

  .detail-header {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: var(--space-6);
  }

  .back-btn {
    background: none;
    border: 1px solid var(--color-btn-border);
    border-radius: var(--radius);
    color: var(--color-text-muted);
    padding: 0.2rem 0.5rem;
    font-size: var(--text-sm);
    cursor: pointer;
  }

  .back-btn:hover { color: var(--color-text); }

  .chip-list {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    margin-bottom: 1rem;
    min-height: 1.5rem;
  }

  .chip {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    font-size: var(--text-sm);
    padding: 0.15rem 0.5rem;
    border: 1px solid var(--color-btn-border);
    border-radius: var(--radius);
    background: var(--color-btn-bg);
  }

  .chip-remove {
    background: none;
    border: none;
    color: var(--color-text-dim);
    cursor: pointer;
    font-size: 1rem;
    line-height: 1;
    padding: 0 0.1rem;
  }

  .chip-remove:hover { color: var(--color-danger); }

  .empty-hint {
    color: var(--color-text-dim);
    font-size: var(--text-sm);
    font-style: italic;
  }

  .add-section {
    border-top: 1px dotted var(--color-border);
    padding-top: 0.75rem;
  }

  .hint {
    font-size: var(--text-xs);
    color: var(--color-text-dim);
    margin-top: 0.25rem;
  }

  .modal-hint {
    font-size: var(--text-sm);
    color: var(--color-text-dim);
    margin-top: 0.5rem;
  }
</style>
