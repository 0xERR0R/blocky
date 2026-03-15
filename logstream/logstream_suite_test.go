// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package logstream_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestLogstream(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Logstream Suite")
}
