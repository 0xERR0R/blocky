const BASE = '/api/config'

async function request(method, path, body) {
  const opts = {
    method,
    headers: {},
  }

  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(body)
  }

  const resp = await fetch(BASE + path, opts)

  if (resp.status === 204) return null

  const data = await resp.json()

  if (!resp.ok) {
    throw new Error(data.error || `${resp.status} ${resp.statusText}`)
  }

  return data
}

// Client Groups
export const clientGroups = {
  list: () => request('GET', '/client-groups'),
  get: (name) => request('GET', `/client-groups/${name}`),
  put: (name, body) => request('PUT', `/client-groups/${name}`, body),
  delete: (name) => request('DELETE', `/client-groups/${name}`),
}

// Blocklist Sources
export const blocklistSources = {
  list: (params) => {
    const qs = params ? '?' + new URLSearchParams(params) : ''
    return request('GET', `/blocklist-sources${qs}`)
  },
  get: (id) => request('GET', `/blocklist-sources/${id}`),
  create: (body) => request('POST', '/blocklist-sources', body),
  update: (id, body) => request('PUT', `/blocklist-sources/${id}`, body),
  delete: (id) => request('DELETE', `/blocklist-sources/${id}`),
}

// Custom DNS
export const customDNS = {
  list: (params) => {
    const qs = params ? '?' + new URLSearchParams(params) : ''
    return request('GET', `/custom-dns${qs}`)
  },
  get: (id) => request('GET', `/custom-dns/${id}`),
  create: (body) => request('POST', '/custom-dns', body),
  update: (id, body) => request('PUT', `/custom-dns/${id}`, body),
  delete: (id) => request('DELETE', `/custom-dns/${id}`),
}

// Block Settings
export const blockSettings = {
  get: () => request('GET', '/block-settings'),
  update: (body) => request('PUT', '/block-settings', body),
}

// Discovered Clients (ARP-based network discovery)
export async function getDiscoveredClients() {
  const resp = await fetch('/api/discovered-clients')
  if (!resp.ok) return []
  return resp.json()
}

// Apply
export const apply = () => request('POST', '/apply')

// Stats
export async function getStats() {
  const resp = await fetch('/api/stats')
  if (!resp.ok) return null
  return resp.json()
}
