package web

import (
	"embed"
	"io/fs"
)

//go:embed all:ui/dist
var uiFS embed.FS

// UIAssets returns the built Svelte UI files for serving.
func UIAssets() (fs.FS, error) {
	return fs.Sub(uiFS, "ui/dist")
}
