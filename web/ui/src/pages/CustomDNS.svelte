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
  import { customDNS } from '../lib/api.js'
  import { markDirty } from '../lib/dirty.svelte.js'

  let entries = $state([])
  let loading = $state(true)
  let editOpen = $state(false)
  let editId = $state(null)
  let form = $state({ domain: '', record_type: 'A', value: '', ttl: 3600, enabled: true })

  const columns = [
    { key: 'domain', label: 'Domain', sortable: true },
    { key: 'record_type', label: 'Type' },
    { key: 'value', label: 'Value' },
    { key: 'ttl', label: 'TTL' },
    { key: 'enabled', label: 'Status', render: (r) => r.enabled ? '✓' : '—' },
  ]

  async function load() {
    loading = true
    try { entries = await customDNS.list() ?? [] } catch { entries = [] }
    loading = false
  }

  function openNew() {
    editId = null
    form = { domain: '', record_type: 'A', value: '', ttl: 3600, enabled: true }
    editOpen = true
  }

  function openEdit(row) {
    editId = row.id
    form = { ...row }
    editOpen = true
  }

  async function save() {
    if (editId) {
      await customDNS.update(editId, form)
    } else {
      await customDNS.create(form)
    }
    editOpen = false
    markDirty()
    await load()
  }

  async function remove(id) {
    await customDNS.delete(id)
    markDirty()
    await load()
  }

  load()
</script>

<div class="page">
  <h1 class="page-title">Custom DNS</h1>

  <Card>
    {#snippet actions()}
      <Button size="sm" onclick={openNew}>Add Entry</Button>
    {/snippet}
    {#if loading}
      <EmptyState message="Loading..." />
    {:else if entries.length === 0}
      <EmptyState message="no custom dns entries">
        <Button size="sm" onclick={openNew}>Add your first entry</Button>
      </EmptyState>
    {:else}
      <DataTable {columns} rows={entries}>
        {#snippet rowActions(row)}
          <Button size="sm" onclick={() => openEdit(row)}>Edit</Button>
          <Button size="sm" variant="danger" onclick={() => remove(row.id)}>Delete</Button>
        {/snippet}
      </DataTable>
    {/if}
  </Card>
</div>

<Modal bind:open={editOpen} title={editId ? 'Edit DNS Entry' : 'New DNS Entry'}>
  <FormField label="Domain">
    <TextInput bind:value={form.domain} placeholder="myhost.lan" />
  </FormField>
  <FormField label="Record Type">
    <Select bind:value={form.record_type} options={[
      { value: 'A', label: 'A (IPv4)' },
      { value: 'AAAA', label: 'AAAA (IPv6)' },
      { value: 'CNAME', label: 'CNAME' },
    ]} />
  </FormField>
  <FormField label="Value">
    <TextInput bind:value={form.value} placeholder="192.168.1.100" />
  </FormField>
  <FormField label="TTL (seconds)">
    <TextInput bind:value={form.ttl} type="number" placeholder="3600" />
  </FormField>
  <FormField label="Enabled">
    <Toggle bind:checked={form.enabled} />
  </FormField>
  {#snippet actions()}
    <Button onclick={() => editOpen = false}>Cancel</Button>
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
