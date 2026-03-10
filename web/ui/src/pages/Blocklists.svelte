<script>
  import Card from '../components/Card.svelte'
  import Button from '../components/Button.svelte'
  import DataTable from '../components/DataTable.svelte'
  import Modal from '../components/Modal.svelte'
  import FormField from '../components/FormField.svelte'
  import TextInput from '../components/TextInput.svelte'
  import Select from '../components/Select.svelte'
  import Toggle from '../components/Toggle.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import Badge from '../components/Badge.svelte'
  import { blocklistSources } from '../lib/api.js'
  import { markDirty } from '../lib/dirty.svelte.js'

  let sources = $state([])
  let loading = $state(true)
  let editOpen = $state(false)
  let editId = $state(null)
  let form = $state({ group_name: '', list_type: 'deny', source_type: 'http', source: '', enabled: true })

  const columns = [
    { key: 'group_name', label: 'Group', sortable: true },
    { key: 'list_type', label: 'Type', render: (r) => r.list_type === 'deny' ? 'Deny' : 'Allow' },
    { key: 'source_type', label: 'Source Type' },
    { key: 'source', label: 'Source' },
    { key: 'enabled', label: 'Status', render: (r) => r.enabled ? '✓' : '—' },
  ]

  async function load() {
    loading = true
    try { sources = await blocklistSources.list() ?? [] } catch { sources = [] }
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
          <Button size="sm" onclick={() => openEdit(row)}>edit</Button>
          <Button size="sm" variant="danger" onclick={() => remove(row.id)}>delete</Button>
        {/snippet}
      </DataTable>
    {/if}
  </Card>
</div>

<Modal bind:open={editOpen} title={editId ? 'Edit Source' : 'New Blocklist Source'}>
  <FormField label="Group Name">
    <TextInput bind:value={form.group_name} placeholder="e.g. ads" />
  </FormField>
  <FormField label="List Type">
    <Select bind:value={form.list_type} options={[
      { value: 'deny', label: 'Deny (blocklist)' },
      { value: 'allow', label: 'Allow (whitelist)' },
    ]} />
  </FormField>
  <FormField label="Source Type">
    <Select bind:value={form.source_type} options={[
      { value: 'http', label: 'HTTP URL' },
      { value: 'file', label: 'Local File' },
      { value: 'inline', label: 'Inline Text' },
    ]} />
  </FormField>
  <FormField label="Source">
    <TextInput bind:value={form.source} placeholder="https://example.com/blocklist.txt" />
  </FormField>
  <FormField label="Enabled">
    <Toggle bind:checked={form.enabled} />
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
