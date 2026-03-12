// Theme state with localStorage persistence

const STORAGE_KEY = 'blocky-theme'

let theme = $state(localStorage.getItem(STORAGE_KEY) || 'light')

document.documentElement.setAttribute('data-theme', theme)

export function getTheme() {
  return theme
}

export function toggleTheme() {
  theme = theme === 'light' ? 'dark' : 'light'
  document.documentElement.setAttribute('data-theme', theme)
  localStorage.setItem(STORAGE_KEY, theme)
}
