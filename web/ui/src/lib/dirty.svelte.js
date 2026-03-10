// Tracks pending changes count across all config pages

let count = $state(0)
let listeners = new Set()

export function getDirtyCount() {
  return count
}

export function markDirty() {
  count++
  notify()
}

export function clearDirty() {
  count = 0
  notify()
}

export function onDirtyChange(fn) {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

function notify() {
  for (const fn of listeners) fn(count)
}
