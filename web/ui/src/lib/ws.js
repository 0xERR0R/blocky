// WebSocket log stream with auto-reconnect

export function connectLogStream(onEntry, onStatus) {
  let ws
  let reconnectTimer
  let alive = true

  function connect() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    ws = new WebSocket(`${proto}//${location.host}/api/ws/logs`)

    ws.onopen = () => onStatus(true)

    ws.onmessage = (evt) => {
      try {
        onEntry(JSON.parse(evt.data))
      } catch { /* ignore malformed */ }
    }

    ws.onclose = () => {
      onStatus(false)
      if (alive) {
        reconnectTimer = setTimeout(connect, 3000)
      }
    }

    ws.onerror = () => ws.close()
  }

  connect()

  return function disconnect() {
    alive = false
    clearTimeout(reconnectTimer)
    if (ws) ws.close()
  }
}
