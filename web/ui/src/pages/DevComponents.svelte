<script>
  import Button from '../components/Button.svelte'
  import Badge from '../components/Badge.svelte'
  import Card from '../components/Card.svelte'
  import TextInput from '../components/TextInput.svelte'
  import FormField from '../components/FormField.svelte'
  import Select from '../components/Select.svelte'
  import Toggle from '../components/Toggle.svelte'
  import Spinner from '../components/Spinner.svelte'
  import Modal from '../components/Modal.svelte'
  import Toast from '../components/Toast.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import DataTable from '../components/DataTable.svelte'
  import LogViewer from '../components/LogViewer.svelte'
  import StatusBar from '../components/StatusBar.svelte'
  import ApplyButton from '../components/ApplyButton.svelte'
  import RadioGroup from '../components/RadioGroup.svelte'

  let modalOpen = $state(false)
  let toastVisible = $state(false)
  let toggleChecked = $state(true)
  let inputValue = $state('')
  let selectValue = $state('opt1')
  let radioValue = $state('opt1')

  const tableColumns = [
    { key: 'name', label: 'name', sortable: true },
    { key: 'type', label: 'type', sortable: true },
    { key: 'status', label: 'status' },
  ]

  const tableRows = [
    { name: 'ads', type: 'deny', status: 'active' },
    { name: 'malware', type: 'deny', status: 'active' },
    { name: 'whitelist', type: 'allow', status: 'inactive' },
  ]

  const sampleLogs = [
    { timestamp: new Date().toISOString(), level: 'info', message: 'Server started on :4000' },
    { timestamp: new Date().toISOString(), level: 'debug', message: 'Loading blocklist from https://example.com/list.txt' },
    { timestamp: new Date().toISOString(), level: 'warn', message: 'Slow upstream response: 2.3s' },
    { timestamp: new Date().toISOString(), level: 'error', message: 'Failed to refresh list: connection timeout' },
    { timestamp: new Date().toISOString(), level: 'info', message: 'Query google.com from 192.168.1.42 -> RESOLVED (12ms)' },
    { timestamp: new Date().toISOString(), level: 'info', message: 'Query github.com from 192.168.1.10 -> RESOLVED (8ms)' },
    { timestamp: new Date().toISOString(), level: 'debug', message: 'Cache hit for cdn.example.com' },
    { timestamp: new Date().toISOString(), level: 'info', message: 'Query api.stripe.com from 192.168.1.42 -> RESOLVED (15ms)' },
    { timestamp: new Date().toISOString(), level: 'warn', message: 'Upstream 1.1.1.1 latency: 450ms' },
    { timestamp: new Date().toISOString(), level: 'error', message: 'Blocklist update failed: DNS resolution error' },
    { timestamp: new Date().toISOString(), level: 'info', message: 'Query example.org from 192.168.1.55 -> RESOLVED (3ms)' },
    { timestamp: new Date().toISOString(), level: 'debug', message: 'Refreshing blocklist: ads.txt (24891 entries)' },
    { timestamp: new Date().toISOString(), level: 'info', message: 'Query fonts.googleapis.com from 192.168.1.10 -> RESOLVED (11ms)' },
    { timestamp: new Date().toISOString(), level: 'warn', message: 'Rate limit approaching for 192.168.1.99' },
    { timestamp: new Date().toISOString(), level: 'info', message: 'Blocklist refresh complete: 3 lists, 148201 entries' },
  ]
</script>

<div class="dev">
  <h1>the blocky style guide</h1>

  <!-- Colors -->
  <div class="box">
    <h2>colors</h2>
    <div class="swatch-grid">
      <div class="swatch" style="background: var(--color-bg); color: var(--color-text-muted)"><span>bg</span></div>
      <div class="swatch" style="background: var(--color-surface); color: var(--color-text-muted)"><span>surface</span></div>
      <div class="swatch" style="background: var(--color-surface-raised); color: var(--color-text-muted)"><span>raised</span></div>
      <div class="swatch" style="background: var(--color-primary); color: var(--color-primary-fg)"><span>primary</span></div>
      <div class="swatch" style="background: var(--color-accent); color: var(--color-success-fg)"><span>accent</span></div>
      <div class="swatch" style="background: var(--color-danger); color: var(--color-danger-fg)"><span>danger</span></div>
      <div class="swatch" style="background: var(--color-warning); color: var(--color-warning-fg)"><span>warning</span></div>
      <div class="swatch" style="background: var(--color-info); color: var(--color-info-fg)"><span>info</span></div>
    </div>
  </div>

  <!-- Typography -->
  <div class="box">
    <h2>typography</h2>
    <p style="font-size: var(--text-2xl); font-weight: 700">heading 2xl (1.4rem)</p>
    <p style="font-size: var(--text-xl); font-weight: 700">heading xl (1.1rem)</p>
    <p style="font-size: var(--text-lg); font-weight: 700">heading lg (1rem)</p>
    <p style="font-size: var(--text-base)">body base (0.9rem)</p>
    <p style="font-size: var(--text-sm); color: var(--color-text-muted)">body small (0.8rem)</p>
    <p style="font-size: var(--text-xs); color: var(--color-text-dim)">caption (0.72rem)</p>
    <p style="font-size: var(--text-sm)">all Inconsolata — monospace everywhere</p>
  </div>

  <!-- Buttons -->
  <div class="box">
    <h2>buttons</h2>
    <div class="row">
      <Button>default</Button>
      <Button variant="primary">primary</Button>
      <Button variant="accent">accent</Button>
      <Button variant="danger">danger</Button>
      <Button variant="ghost">ghost</Button>
    </div>
    <div class="row">
      <Button loading={true}>loading</Button>
      <Button disabled={true}>disabled</Button>
    </div>
    <div class="row">
      <Button size="sm">small</Button>
      <Button size="md">medium</Button>
      <Button size="lg">large</Button>
    </div>
  </div>

  <!-- Badges -->
  <div class="box">
    <h2>badges</h2>
    <div class="row">
      <Badge variant="success">active</Badge>
      <Badge variant="warning">pending</Badge>
      <Badge variant="danger">error</Badge>
      <Badge variant="info">info</Badge>
      <Badge variant="neutral">default</Badge>
    </div>
  </div>

  <!-- Form Controls -->
  <div class="box">
    <h2>form controls</h2>
    <div class="grid-2">
      <div>
        <FormField label="text input">
          <TextInput bind:value={inputValue} placeholder="type something..." />
        </FormField>
        <FormField label="with error" error="this field is required">
          <TextInput value="" placeholder="invalid input" />
        </FormField>
      </div>
      <div>
        <FormField label="select">
          <Select
            bind:value={selectValue}
            options={[
              { value: 'opt1', label: 'option one' },
              { value: 'opt2', label: 'option two' },
              { value: 'opt3', label: 'option three' },
            ]}
          />
        </FormField>
        <FormField label="toggle">
          <Toggle bind:checked={toggleChecked} label="enable feature" />
        </FormField>
      </div>
    </div>
  </div>

  <!-- Radio Buttons -->
  <div class="box">
    <h2>radio buttons</h2>
    <div class="grid-2">
      <RadioGroup
        name="demo"
        bind:value={radioValue}
        options={[
          { value: 'opt1', label: 'option one' },
          { value: 'opt2', label: 'option two' },
          { value: 'opt3', label: 'option three' },
        ]}
      />
      <RadioGroup
        name="demo-disabled"
        value="opt1"
        disabled={true}
        options={[
          { value: 'opt1', label: 'enabled' },
          { value: 'opt2', label: 'disabled' },
        ]}
      />
    </div>
  </div>

  <!-- Cards -->
  <div class="box">
    <h2>cards (boxes)</h2>
    <div class="grid-2">
      <Card title="basic card">
        <p class="dim">card body content with descriptive text.</p>
      </Card>
      <Card title="with actions">
        {#snippet actions()}
          <Button size="sm" variant="ghost">edit</Button>
        {/snippet}
        <p class="dim">card with action buttons in header.</p>
      </Card>
    </div>
  </div>

  <!-- Data Table -->
  <div class="box">
    <h2>data table</h2>
    <DataTable columns={tableColumns} rows={tableRows}>
      {#snippet rowActions(row)}
        <Button size="sm">edit</Button>
        <Button size="sm" variant="danger">delete</Button>
      {/snippet}
    </DataTable>
  </div>

  <!-- Empty State -->
  <div class="box">
    <h2>empty state</h2>
    <EmptyState message="no results found">
      <Button size="sm">clear filters</Button>
    </EmptyState>
  </div>

  <!-- Log Viewer -->
  <div class="box">
    <h2>log viewer</h2>
    <div class="log-container">
      <LogViewer entries={sampleLogs} connected={true} />
    </div>
  </div>

  <!-- Apply Button -->
  <div class="box">
    <h2>apply button</h2>
    <ApplyButton pending={3} />
  </div>

  <!-- Modal -->
  <div class="box">
    <h2>modal</h2>
    <Button onclick={() => modalOpen = true}>open modal</Button>
    <Modal bind:open={modalOpen} title="confirm action">
      <p>are you sure you want to proceed?</p>
      {#snippet actions()}
        <Button onclick={() => modalOpen = false}>cancel</Button>
        <Button variant="accent" onclick={() => modalOpen = false}>confirm</Button>
      {/snippet}
    </Modal>
  </div>

  <!-- Toast -->
  <div class="box">
    <h2>toast</h2>
    <Button onclick={() => toastVisible = true}>show toast</Button>
    <Toast bind:visible={toastVisible} variant="success" duration={3000}>
      changes saved successfully
    </Toast>
  </div>

  <!-- Spinner -->
  <div class="box">
    <h2>spinner</h2>
    <div class="row">
      <Spinner size={12} />
      <Spinner size={16} />
      <Spinner size={24} />
      <Spinner size={32} />
    </div>
  </div>

  <!-- Status Bar -->
  <div class="box">
    <h2>status bar</h2>
    <StatusBar connected={true} version="1.0.0" pendingChanges={2} />
  </div>
</div>

<style>
  .dev {
    max-width: 900px;
    margin: 0 auto;
  }

  h1 {
    font-size: var(--text-2xl);
    font-weight: 700;
    margin-bottom: 1.5rem;
  }

  .box {
    border: 1px solid var(--color-border);
    padding: 1.5rem;
    margin-bottom: 1rem;
    background: var(--color-surface);
    border-radius: var(--radius);
  }

  h2 {
    font-size: var(--text-sm);
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--color-text-muted);
    margin-bottom: 0.75rem;
    padding-bottom: 0.25rem;
    border-bottom: 1px dotted var(--color-border-subtle);
  }

  .row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin-bottom: 0.5rem;
  }

  .grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }

  .swatch-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(90px, 1fr));
    gap: 0.5rem;
  }

  .swatch {
    height: 48px;
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    display: flex;
    align-items: flex-end;
    padding: 0.25rem;
  }

  .swatch span {
    font-size: var(--text-xs);
    font-weight: 700;
    color: inherit;
  }

  .dim {
    color: var(--color-text-muted);
    font-size: var(--text-sm);
  }

  .log-container {
    height: 220px;
  }
</style>
