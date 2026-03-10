<script>
  import Card from '../components/Card.svelte'
  import Button from '../components/Button.svelte'
  import DataTable from '../components/DataTable.svelte'
  import Modal from '../components/Modal.svelte'
  import FormField from '../components/FormField.svelte'
  import TextInput from '../components/TextInput.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import Badge from '../components/Badge.svelte'
  import { clientGroups } from '../lib/api.js'
  import { markDirty } from '../lib/dirty.svelte.js'

  let groups = $state([])
  let loading = $state(true)
  let editOpen = $state(false)
  let editName = $state('')
  let editClients = $state('')
  let editGroups = $state('')
  let isNew = $state(true)

  const columns = [
    { key: 'name', label: 'Name', sortable: true },
    { key: 'clients', label: 'Clients', render: (r) => r.clients?.join(', ') || '' },
    { key: 'groups', label: 'Groups', render: (r) => r.groups?.join(', ') || '' },
  ]

  async function load() {
    loading = true
    try { groups = await clientGroups.list() ?? [] } catch { groups = [] }
    loading = false
  }

  function openNew() {
    isNew = true
    editName = ''
    editClients = ''
    editGroups = ''
    editOpen = true
  }

  function openEdit(row) {
    isNew = false
    editName = row.name
    editClients = row.clients?.join(', ') || ''
    editGroups = row.groups?.join(', ') || ''
    editOpen = true
  }

  async function save() {
    const body = {
      clients: editClients.split(',').map(s => s.trim()).filter(Boolean),
      groups: editGroups.split(',').map(s => s.trim()).filter(Boolean),
    }
    await clientGroups.put(editName, body)
    editOpen = false
    markDirty()
    await load()
  }

  async function remove(name) {
    await clientGroups.delete(name)
    markDirty()
    await load()
  }

  load()
</script>

<div class="page">
  <h1 class="page-title">Client Groups</h1>

  <Card>
    {#snippet actions()}
      <Button size="sm" onclick={openNew}>Add Group</Button>
    {/snippet}
    {#if loading}
      <EmptyState message="Loading..." />
    {:else if groups.length === 0}
      <EmptyState message="no client groups configured">
        <Button size="sm" onclick={openNew}>Create your first group</Button>
      </EmptyState>
    {:else}
      <DataTable {columns} rows={groups}>
        {#snippet rowActions(row)}
          <Button size="sm" onclick={() => openEdit(row)}>edit</Button>
          <Button size="sm" variant="danger" onclick={() => remove(row.name)}>delete</Button>
        {/snippet}
      </DataTable>
    {/if}
  </Card>
</div>

<Modal bind:open={editOpen} title={isNew ? 'New Client Group' : `Edit: ${editName}`}>
  {#if isNew}
    <FormField label="Name">
      <TextInput bind:value={editName} placeholder="e.g. kids" />
    </FormField>
  {/if}
  <FormField label="Clients (comma-separated)">
    <TextInput bind:value={editClients} placeholder="192.168.1.0/24, 10.0.0.5" />
  </FormField>
  <FormField label="Groups (comma-separated)">
    <TextInput bind:value={editGroups} placeholder="ads, malware" />
  </FormField>
  {#snippet actions()}
    <Button onclick={() => editOpen = false}>cancel</Button>
    <Button onclick={save}>Save</Button>
  {/snippet}
</Modal>

<style>
  .page { max-width: 1000px; }
  .page-title {
    font-size: var(--text-2xl);
    font-weight: 700;
    margin-bottom: var(--space-6);
  }
</style>
