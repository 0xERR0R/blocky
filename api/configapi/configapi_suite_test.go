// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package configapi_test

import (
	"testing"

	"github.com/0xERR0R/blocky/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func init() {
	log.Silence()
}

func TestConfigAPI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config API Suite")
}
