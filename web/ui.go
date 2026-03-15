// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

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
