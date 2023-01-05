//go:build tools
// +build tools

// see https://play-with-go.dev/tools-as-dependencies_go115_en/
// and https://www.jvt.me/posts/2022/06/15/go-tools-dependency-management/
package tools

import (
	_ "github.com/abice/go-enum"
	_ "github.com/dosgo/zigtool/zigcc"
	_ "github.com/dosgo/zigtool/zigcpp"
	_ "github.com/onsi/ginkgo/v2/ginkgo"
	_ "github.com/swaggo/swag/cmd/swag"
	_ "mvdan.cc/gofumpt"
)
