<script>
  let { entries = [], connected = false, autoscroll = true } = $props()
  let container

  $effect(() => {
    if (autoscroll && entries.length && container) {
      container.scrollTop = container.scrollHeight
    }
  })

  function levelClass(level) {
    const map = { error: 'err', warn: 'warn', warning: 'warn', info: 'ok', debug: 'dim' }
    return map[level?.toLowerCase()] || 'dim'
  }

  function formatTime(ts) {
    if (!ts) return ''
    const d = new Date(ts)
    return d.toLocaleTimeString('en-GB', { hour12: false, fractionalSecondDigits: 3 })
  }

  function formatMessage(entry) {
    const f = entry.fields
    if (f && f.question_name) {
      const qtype = (f.question_type || '').padEnd(5)
      const rcode = f.response_code || ''
      const reason = f.response_reason ? ` (${f.response_reason})` : ''
      const dur = f.duration_ms != null ? `  ${f.duration_ms}ms` : ''
      return `${qtype}  ${f.question_name}  ${rcode}${reason}${dur}`
    }
    return entry.message
  }
</script>

<div class="log-viewer">
  <div class="log-header">
    <span class="dot" class:connected></span>
    <span>{connected ? 'live' : 'disconnected'}</span>
    <span class="count">{entries.length} entries</span>
  </div>
  <div class="log-body" bind:this={container}>
{#each entries as entry}<div class="log-{levelClass(entry.level)}">{formatTime(entry.timestamp)}  {(entry.level || '').padEnd(5)}  {formatMessage(entry)}</div>{:else}<span class="log-dim">waiting for data...</span>{/each}
  </div>
</div>

<style>
  .log-viewer {
    display: flex;
    flex-direction: column;
    height: 100%;
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    overflow: hidden;
  }

  .log-header {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: 0.25rem 0.5rem;
    border-bottom: 1px dotted var(--color-border);
    font-size: var(--text-xs);
    color: var(--color-text-muted);
  }

  .dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--color-danger);
  }

  .dot.connected {
    background: var(--color-accent);
    box-shadow: 0 0 6px var(--color-accent);
  }

  .count {
    margin-left: auto;
  }

  .log-body {
    flex: 1;
    overflow-y: auto;
    font-size: var(--text-xs);
    line-height: 1.2;
    padding: 0.5rem;
    white-space: pre;
    background: var(--color-bg);
    color: var(--color-text-muted);
  }

  .log-ok { color: var(--color-accent); }
  .log-err { color: var(--color-danger); }
  .log-warn { color: var(--color-warning); }
  .log-dim { color: var(--color-text-dim); }
</style>
