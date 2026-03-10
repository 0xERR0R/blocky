<script>
  import Card from '../components/Card.svelte'
  import Button from '../components/Button.svelte'
  import FormField from '../components/FormField.svelte'
  import Select from '../components/Select.svelte'
  import TextInput from '../components/TextInput.svelte'
  import Toast from '../components/Toast.svelte'
  import { blockSettings } from '../lib/api.js'
  import { markDirty } from '../lib/dirty.svelte.js'

  let blockType = $state('ZEROIP')
  let blockTTL = $state('1m')
  let loading = $state(true)
  let saving = $state(false)
  let toastVisible = $state(false)
  let toastMessage = $state('')
  let toastVariant = $state('success')

  async function load() {
    loading = true
    try {
      const data = await blockSettings.get()
      blockType = data.block_type || 'ZEROIP'
      blockTTL = data.block_ttl || '1m'
    } catch { /* use defaults */ }
    loading = false
  }

  async function save() {
    saving = true
    try {
      await blockSettings.update({ block_type: blockType, block_ttl: blockTTL })
      markDirty()
      toastVariant = 'success'
      toastMessage = 'Block settings saved'
    } catch (e) {
      toastVariant = 'danger'
      toastMessage = e.message
    }
    saving = false
    toastVisible = true
  }

  load()
</script>

<div class="page">
  <h1 class="page-title">Block Settings</h1>

  <Card title="Response Behavior" loading={loading}>
    <div class="form-layout">
      <FormField label="Block Type">
        <Select bind:value={blockType} options={[
          { value: 'ZEROIP', label: 'Zero IP (0.0.0.0)' },
          { value: 'NXDOMAIN', label: 'NXDOMAIN' },
        ]} />
      </FormField>
      <FormField label="Block TTL">
        <TextInput bind:value={blockTTL} placeholder="1m, 30s, 1h" />
      </FormField>
      <div class="form-actions">
        <Button onclick={save} loading={saving}>Save Settings</Button>
      </div>
    </div>
  </Card>
</div>

<Toast bind:visible={toastVisible} variant={toastVariant}>{toastMessage}</Toast>

<style>
  .page { max-width: 600px; }
  .page-title {
    font-size: var(--text-2xl);
    font-weight: 700;
    margin-bottom: var(--space-6);
  }
  .form-layout {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .form-actions {
    display: flex;
    justify-content: flex-end;
    padding-top: var(--space-2);
  }
</style>
