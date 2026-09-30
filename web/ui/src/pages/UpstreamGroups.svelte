<!-- Copyright 2026 Chris Snell -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script>
  import {
    Box,
    Button,
    Table,
    Modal,
    Label,
    Input,
    Select,
    Toggle,
    EmptyState,
    Toaster,
    toast,
  } from '@chrissnell/chonky-ui'
  import { upstreamGroups, upstreamSettings } from '../lib/api.js'
  import { markDirty } from '../lib/dirty.svelte.js'

  // --- Settings ---
  let strategy = $state('parallel_best')
  let timeout = $state('2s')
  let userAgent = $state('')
  let initStrategy = $state('blocking')
  let settingsLoading = $state(true)
  let settingsSaving = $state(false)

  async function loadSettings() {
    settingsLoading = true
    try {
      const data = await upstreamSettings.get()
      strategy = data.strategy || 'parallel_best'
      timeout = data.timeout || '2s'
      userAgent = data.user_agent || ''
      initStrategy = data.init_strategy || 'blocking'
    } catch (e) {
      toast(e.message, 'danger')
    }
    settingsLoading = false
  }

  async function saveSettings() {
    settingsSaving = true
    try {
      await upstreamSettings.update({
        strategy,
        timeout,
        user_agent: userAgent,
        init_strategy: initStrategy,
      })
      markDirty()
      toast('Upstream settings saved', 'success')
    } catch (e) {
      toast(e.message, 'danger')
    }
    settingsSaving = false
  }

  // --- Groups list ---
  let groups = $state([])
  let loading = $state(true)

  // Servers keyed by group name
  let serversByGroup = $state({})

  // Create group modal
  let createOpen = $state(false)
  let createName = $state('')

  // Server edit modal
  let serverOpen = $state(false)
  let serverEditId = $state(null)
  let serverGroup = $state('')
  let serverForm = $state({ protocol: 'plain', host: '', enabled: true, position: 0 })

  // Split a stored upstream URL into (protocol, host).
  //   "1.1.1.1"                        -> plain,   "1.1.1.1"
  //   "tcp-tls:dns.example.com"        -> tcp-tls, "dns.example.com"
  //   "https://dns.google/dns-query"   -> https,   "dns.google/dns-query"
  //   "quic:dns.adguard.com"           -> quic,    "dns.adguard.com"
  // Both "quic:" and "quic://" are accepted on read; "quic:" is the canonical form.
  function splitUrl(url) {
    const u = (url ?? '').trim()
    if (u.startsWith('https://')) return { protocol: 'https', host: u.slice('https://'.length) }
    if (u.startsWith('tcp-tls:')) return { protocol: 'tcp-tls', host: u.slice('tcp-tls:'.length) }
    if (u.startsWith('quic:')) return { protocol: 'quic', host: u.replace(/^quic:(\/\/)?/, '') }
    return { protocol: 'plain', host: u }
  }

  function joinUrl(protocol, host) {
    const h = (host ?? '').trim()
    if (protocol === 'https') return `https://${h.replace(/^https:\/\//, '')}`
    if (protocol === 'tcp-tls') return `tcp-tls:${h.replace(/^tcp-tls:/, '')}`
    if (protocol === 'quic') return `quic:${h.replace(/^quic:(\/\/)?/, '')}`
    return h
  }

  // Detect a pasted full URL in the host field and auto-split into protocol + host.
  function cleanHostInput() {
    const h = (serverForm.host ?? '').trim()
    if (h.startsWith('https://')) {
      serverForm.protocol = 'https'
      serverForm.host = h.slice('https://'.length)
    } else if (h.startsWith('tcp-tls:')) {
      serverForm.protocol = 'tcp-tls'
      serverForm.host = h.slice('tcp-tls:'.length)
    } else if (h.startsWith('quic:')) {
      serverForm.protocol = 'quic'
      serverForm.host = h.replace(/^quic:(\/\/)?/, '')
    }
  }

  async function loadGroups() {
    loading = true
    try {
      groups = (await upstreamGroups.list()) ?? []
      const entries = await Promise.all(
        groups.map(async (g) => [g.name, (await upstreamGroups.listServers(g.name)) ?? []]),
      )
      serversByGroup = Object.fromEntries(entries)
    } catch (e) {
      toast(e.message, 'danger')
      groups = []
      serversByGroup = {}
    }
    loading = false
  }

  // --- Group CRUD ---
  function openCreate() {
    createName = ''
    createOpen = true
  }

  async function createGroup() {
    const name = createName.trim()
    if (!name) return
    try {
      await upstreamGroups.put(name)
      createOpen = false
      markDirty()
      await loadGroups()
    } catch (e) {
      toast(e.message, 'danger')
    }
  }

  async function removeGroup(name) {
    if (name === 'default') return
    if (!confirm(`Delete upstream group "${name}" and all its servers?`)) return
    try {
      await upstreamGroups.delete(name)
      markDirty()
      await loadGroups()
    } catch (e) {
      toast(e.message, 'danger')
    }
  }

  // --- Server CRUD ---
  function openNewServer(groupName) {
    serverEditId = null
    serverGroup = groupName
    const existing = serversByGroup[groupName] ?? []
    serverForm = { protocol: 'plain', host: '', enabled: true, position: existing.length }
    serverOpen = true
  }

  function openEditServer(groupName, row) {
    serverEditId = row.id
    serverGroup = groupName
    const { protocol, host } = splitUrl(row.url)
    serverForm = { protocol, host, enabled: row.enabled, position: row.position }
    serverOpen = true
  }

  async function saveServer() {
    try {
      const body = {
        url: joinUrl(serverForm.protocol, serverForm.host),
        enabled: serverForm.enabled,
        position: Number(serverForm.position) || 0,
      }
      if (serverEditId) {
        await upstreamGroups.updateServer(serverGroup, serverEditId, body)
      } else {
        await upstreamGroups.createServer(serverGroup, body)
      }
      serverOpen = false
      markDirty()
      await loadGroups()
    } catch (e) {
      toast(e.message, 'danger')
    }
  }

  async function removeServer(groupName, id) {
    try {
      await upstreamGroups.deleteServer(groupName, id)
      markDirty()
      await loadGroups()
    } catch (e) {
      toast(e.message, 'danger')
    }
  }

  async function moveServer(groupName, index, direction) {
    const list = serversByGroup[groupName] ?? []
    const target = index + direction
    if (target < 0 || target >= list.length) return
    const a = list[index]
    const b = list[target]
    try {
      await upstreamGroups.updateServer(groupName, a.id, {
        url: a.url,
        enabled: a.enabled,
        position: b.position,
      })
      await upstreamGroups.updateServer(groupName, b.id, {
        url: b.url,
        enabled: b.enabled,
        position: a.position,
      })
      markDirty()
      await loadGroups()
    } catch (e) {
      toast(e.message, 'danger')
    }
  }

  loadGroups()
  loadSettings()
</script>

<div class="page">
  <div class="page-header">
    <h1 class="page-title">Upstream Groups</h1>
    <Button size="sm" onclick={openCreate}>Add Group</Button>
  </div>

  {#if loading}
    <Box><EmptyState>Loading...</EmptyState></Box>
  {:else if groups.length === 0}
    <Box>
      <EmptyState>
        <p>no upstream groups</p>
        <Button size="sm" onclick={openCreate}>Add your first group</Button>
      </EmptyState>
    </Box>
  {:else}
    {#each groups as g (g.id)}
      <Box title={g.name}>
        <div class="group-toolbar">
          <Button size="sm" onclick={() => openNewServer(g.name)}>Add Server</Button>
          <Button
            size="sm"
            variant="danger"
            disabled={g.name === 'default'}
            onclick={() => removeGroup(g.name)}
          >
            Delete Group
          </Button>
        </div>
        {#if (serversByGroup[g.name]?.length ?? 0) === 0}
          <EmptyState>
            <p>no servers in this group</p>
            <Button size="sm" onclick={() => openNewServer(g.name)}>Add server</Button>
          </EmptyState>
        {:else}
          <Table>
            <thead>
              <tr>
                <th>URL</th>
                <th>Order</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each serversByGroup[g.name] as srv, i (srv.id)}
                <tr>
                  <td><code>{srv.url}</code></td>
                  <td>
                    <div class="pos-controls">
                      <Button
                        size="sm"
                        disabled={i === 0}
                        onclick={() => moveServer(g.name, i, -1)}
                        aria-label="Move up"
                      >
                        ↑
                      </Button>
                      <Button
                        size="sm"
                        disabled={i === (serversByGroup[g.name]?.length ?? 0) - 1}
                        onclick={() => moveServer(g.name, i, 1)}
                        aria-label="Move down"
                      >
                        ↓
                      </Button>
                    </div>
                  </td>
                  <td>{srv.enabled ? '✓' : '—'}</td>
                  <td class="row-actions">
                    <Button size="sm" onclick={() => openEditServer(g.name, srv)}>Edit</Button>
                    <Button
                      size="sm"
                      variant="danger"
                      onclick={() => removeServer(g.name, srv.id)}
                    >
                      Delete
                    </Button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </Table>
        {/if}
      </Box>
    {/each}
  {/if}

  <div class="settings-section" class:loading-state={settingsLoading}>
    <Box title="Resolver Behavior">
      <div class="form-layout">
        <div class="form-field">
          <Label for="strategy">Resolution Strategy</Label>
          <Select
            id="strategy"
            bind:value={strategy}
            options={[
              { value: 'parallel_best', label: 'Parallel Best (query all, use fastest)' },
              { value: 'strict', label: 'Strict (try in order)' },
              { value: 'random', label: 'Random (pick one)' },
            ]}
          />
          <p class="field-help">
            How queries are sent to the upstream servers in a group. <strong>Parallel Best</strong>
            queries every server at once and uses whichever answers first — fastest but chattiest.
            <strong>Strict</strong> tries servers in order, only moving on if one fails. <strong>Random</strong>
            picks a single server per query to spread load.
          </p>
        </div>
        <div class="form-field">
          <Label for="timeout">Timeout</Label>
          <Input id="timeout" bind:value={timeout} placeholder="2s, 500ms, 1s" />
        </div>
        <div class="form-field">
          <Label for="init-strategy">Init Strategy</Label>
          <Select
            id="init-strategy"
            bind:value={initStrategy}
            options={[
              { value: 'blocking', label: 'Blocking (probe on apply, warn on failure)' },
              { value: 'failOnError', label: 'Fail on error (reject apply if any probe fails)' },
              { value: 'fast', label: 'Fast (no probe)' },
            ]}
          />
          <p class="field-help">
            What happens when the resolver starts up or a config is applied. <strong>Blocking</strong>
            probes each upstream and waits for results, logging a warning if any fail but still
            starting. <strong>Fail on error</strong> refuses to apply the config if any probe fails —
            safest for production. <strong>Fast</strong> skips probes entirely and starts immediately.
          </p>
        </div>
        <div class="form-field">
          <Label for="user-agent">DoH User-Agent</Label>
          <Input id="user-agent" bind:value={userAgent} placeholder="(optional)" />
        </div>
        <div class="form-actions">
          <Button onclick={saveSettings} disabled={settingsSaving}>
            {settingsSaving ? 'Saving...' : 'Save Settings'}
          </Button>
        </div>
      </div>
    </Box>
  </div>
</div>

<Modal bind:open={createOpen}>
  <Modal.Header><h2>New Upstream Group</h2></Modal.Header>
  <Modal.Body>
    <Label>
      Group name
      <Input bind:value={createName} placeholder="kids, iot, work..." />
    </Label>
  </Modal.Body>
  <Modal.Footer>
    <Button onclick={() => (createOpen = false)}>Cancel</Button>
    <Button variant="primary" onclick={createGroup} disabled={!createName.trim()}>
      Create
    </Button>
  </Modal.Footer>
</Modal>

<Modal bind:open={serverOpen}>
  <Modal.Header>
    <h2>{serverEditId ? 'Edit Upstream Server' : 'New Upstream Server'}</h2>
  </Modal.Header>
  <Modal.Body>
    <div class="server-form-row">
      <div class="server-form-protocol">
        <Label for="server-protocol">Protocol</Label>
        <Select
          id="server-protocol"
          bind:value={serverForm.protocol}
          options={[
            { value: 'plain', label: 'plain' },
            { value: 'tcp-tls', label: 'tcp-tls' },
            { value: 'https', label: 'https' },
            { value: 'quic', label: 'quic (DoQ)' },
          ]}
        />
      </div>
      <div class="server-form-host">
        <Label for="server-host">
          {serverForm.protocol === 'https' ? 'Host / path' : 'Host or IP'}
        </Label>
        <Input
          id="server-host"
          bind:value={serverForm.host}
          oninput={cleanHostInput}
          placeholder={serverForm.protocol === 'https'
            ? 'dns.google/dns-query'
            : serverForm.protocol === 'tcp-tls'
              ? 'dns.example.com:853'
              : serverForm.protocol === 'quic'
                ? 'dns.adguard.com'
                : '1.1.1.1'}
        />
      </div>
    </div>
    <Label>
      Position
      <Input bind:value={serverForm.position} type="number" />
    </Label>
    <Toggle bind:checked={serverForm.enabled} label="Enabled" />
  </Modal.Body>
  <Modal.Footer>
    <Button onclick={() => (serverOpen = false)}>Cancel</Button>
    <Button variant="primary" onclick={saveServer}>Save</Button>
  </Modal.Footer>
</Modal>

<Toaster />

<style>
  .page {
    max-width: 1000px;
  }
  .page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
    margin-bottom: var(--space-6);
  }
  .page-title {
    font-size: var(--text-2xl);
    font-weight: 700;
  }
  .row-actions {
    display: flex;
    gap: var(--space-2);
    justify-content: flex-end;
  }
  .group-toolbar {
    display: flex;
    gap: var(--space-2);
    justify-content: flex-end;
    margin-bottom: var(--space-3);
  }
  .pos-controls {
    display: flex;
    gap: var(--space-1);
  }
  .field-help {
    margin-top: var(--space-2);
    font-size: var(--text-sm);
    color: var(--color-text-muted);
    line-height: 1.4;
  }
  .settings-section {
    margin-top: var(--space-6);
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
  .server-form-row {
    display: flex;
    gap: var(--space-3);
    margin-bottom: var(--space-3);
  }
  .server-form-protocol,
  .server-form-host {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }
  .server-form-protocol {
    flex: 0 0 auto;
  }
  .server-form-host {
    flex: 1 1 auto;
    min-width: 0;
  }
</style>
