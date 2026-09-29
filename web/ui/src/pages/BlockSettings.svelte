<!-- Copyright 2026 Chris Snell -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script>
  import { Box, Button, Label, Select, Input, Toaster, toast } from '@chrissnell/chonky-ui'
  import { blockSettings } from '../lib/api.js'
  import { markDirty } from '../lib/dirty.svelte.js'

  const namedBlockTypes = [
    { value: 'ZEROIP', label: 'Zero IP (0.0.0.0)' },
    { value: 'NXDOMAIN', label: 'NXDOMAIN' },
    { value: 'REFUSED', label: 'REFUSED' },
  ]

  let blockType = $state('ZEROIP')
  let blockTTL = $state('1m')
  let loading = $state(true)
  let saving = $state(false)

  // The API also accepts a comma-separated list of block IP addresses, which no
  // named option can represent. Keep a stored value like that selectable so
  // saving an unrelated change doesn't silently rewrite the block type.
  let blockTypeOptions = $derived(
    namedBlockTypes.some((o) => o.value === blockType)
      ? namedBlockTypes
      : [...namedBlockTypes, { value: blockType, label: `${blockType} (custom)` }],
  )

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
      toast('Block settings saved', 'success')
    } catch (e) {
      toast(e.message, 'danger')
    }
    saving = false
  }

  load()
</script>

<div class="page">
  <h1 class="page-title">Block Settings</h1>

  <div class:loading-state={loading}>
    <Box title="Response Behavior">
      <div class="form-layout">
        <div class="form-field">
          <Label for="block-type">Block Type</Label>
          <Select id="block-type" bind:value={blockType} options={blockTypeOptions} />
        </div>
        <div class="form-field">
          <Label for="block-ttl">Block TTL</Label>
          <Input id="block-ttl" bind:value={blockTTL} placeholder="1m, 30s, 1h" />
        </div>
        <div class="form-actions">
          <Button onclick={save} disabled={saving}>
            {saving ? 'Saving...' : 'Save Settings'}
          </Button>
        </div>
      </div>
    </Box>
  </div>
</div>

<Toaster />

<style>
  .page { max-width: 600px; }
  .page-title {
    font-size: var(--text-2xl);
    font-weight: 700;
    margin-bottom: var(--space-6);
  }
  .loading-state {
    opacity: 0.5;
    pointer-events: none;
  }
  .form-layout {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }
  .form-field {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .form-actions {
    display: flex;
    justify-content: flex-end;
    padding-top: var(--space-2);
  }
</style>
