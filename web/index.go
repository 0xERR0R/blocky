package web

import (
	"embed"
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
	return fs.Sub(static, "static")
}
