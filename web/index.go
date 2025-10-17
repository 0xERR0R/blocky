package web

import (
	"embed"
	"fmt"
	"io/fs"
)

// IndexTmpl html template for the start page
//
//go:embed index.html
var IndexTmpl string

//go:embed all:static
var static embed.FS

//go:embed robots.txt
var WebFs embed.FS

func Assets() (fs.FS, error) {
	subFS, err := fs.Sub(static, "static")
	if err != nil {
		return nil, fmt.Errorf("failed to get static assets sub-filesystem: %w", err)
	}

	return subFS, nil
}
