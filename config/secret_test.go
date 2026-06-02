package config

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"
)

var _ = Describe("Secret", func() {
	var tmpDir string

	BeforeEach(func() {
		tmpDir = GinkgoT().TempDir()
	})

	unmarshal := func(value string) (Secret, error) {
		var holder struct {
			S Secret `yaml:"s"`
		}
		err := yaml.UnmarshalStrict([]byte("s: "+value+"\n"), &holder)

		return holder.S, err
	}

	writeFile := func(name, content string) string {
		path := filepath.Join(tmpDir, name)
		Expect(os.WriteFile(path, []byte(content), 0o600)).Should(Succeed())

		return path
	}

	When("the value is a plain literal", func() {
		It("is used verbatim", func() {
			s, err := unmarshal("letmein")
			Expect(err).Should(Succeed())
			Expect(s.Reveal()).Should(Equal("letmein"))
		})
	})

	When("the value has the file: prefix", func() {
		It("reads the file contents", func() {
			path := writeFile("secret", "frompass")

			s, err := unmarshal("file:" + path)
			Expect(err).Should(Succeed())
			Expect(string(s)).Should(Equal("frompass"))
		})

		It("strips a single trailing newline", func() {
			path := writeFile("secret", "frompass\n")

			s, err := unmarshal("file:" + path)
			Expect(err).Should(Succeed())
			Expect(string(s)).Should(Equal("frompass"))
		})

		It("preserves interior and trailing spaces", func() {
			path := writeFile("secret", "with spaces ")

			s, err := unmarshal("file:" + path)
			Expect(err).Should(Succeed())
			Expect(string(s)).Should(Equal("with spaces "))
		})

		It("resolves an empty file to an empty value", func() {
			path := writeFile("secret", "")

			s, err := unmarshal("file:" + path)
			Expect(err).Should(Succeed())
			Expect(string(s)).Should(BeEmpty())
		})

		It("preserves a bare trailing carriage return", func() {
			path := writeFile("secret", "frompass\r")

			s, err := unmarshal("file:" + path)
			Expect(err).Should(Succeed())
			Expect(string(s)).Should(Equal("frompass\r"))
		})

		It("strips a single trailing CRLF", func() {
			path := writeFile("secret", "frompass\r\n")

			s, err := unmarshal("file:" + path)
			Expect(err).Should(Succeed())
			Expect(s.Reveal()).Should(Equal("frompass"))
		})

		It("errors when the file is missing", func() {
			_, err := unmarshal("file:" + filepath.Join(tmpDir, "does-not-exist"))
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("secret file"))
		})

		It("accepts the URI-style file:// prefix", func() {
			path := writeFile("secret", "frompass")

			// path is absolute, so file://<path> yields the file:///abs form.
			s, err := unmarshal("file://" + path)
			Expect(err).Should(Succeed())
			Expect(s.Reveal()).Should(Equal("frompass"))
		})
	})

	Describe("redaction", func() {
		It("redacts via String()", func() {
			Expect(Secret("letmein").String()).Should(Equal(secretObfuscator))
		})

		It("redacts via MarshalText", func() {
			b, err := Secret("letmein").MarshalText()
			Expect(err).Should(Succeed())
			Expect(string(b)).Should(Equal(secretObfuscator))
		})

		It("redacts when marshalled to YAML", func() {
			out, err := yaml.Marshal(struct {
				S Secret `yaml:"s"`
			}{S: "letmein"})
			Expect(err).Should(Succeed())
			Expect(string(out)).ShouldNot(ContainSubstring("letmein"))
			Expect(string(out)).Should(ContainSubstring(secretObfuscator))
		})
	})
})
