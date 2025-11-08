package dnssec

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("TrustAnchorStore", func() {
	Describe("NewTrustAnchorStore", func() {
		When("no custom anchors provided", func() {
			It("should load default root trust anchors", func() {
				store, err := NewTrustAnchorStore(nil)
				Expect(err).Should(Succeed())
				Expect(store).ShouldNot(BeNil())

				// Should have root anchors
				rootAnchors := store.GetRootTrustAnchors()
				Expect(rootAnchors).ShouldNot(BeEmpty())

				// Verify root anchors have expected properties
				for _, anchor := range rootAnchors {
					Expect(anchor.Key).ShouldNot(BeNil())
					Expect(anchor.Key.Flags & 0x0001).Should(Equal(uint16(0x0001))) // SEP flag set
				}
			})

			It("should include KSK-2017 and KSK-2024", func() {
				store, err := NewTrustAnchorStore(nil)
				Expect(err).Should(Succeed())

				rootAnchors := store.GetRootTrustAnchors()
				keyTags := make(map[uint16]bool)
				for _, anchor := range rootAnchors {
					keyTags[anchor.Key.KeyTag()] = true
				}

				// Should have at least one of the known root KSKs
				Expect(keyTags[ksk2017Tag] || keyTags[ksk2024Tag]).Should(BeTrue())
			})
		})

		When("custom anchors provided", func() {
			It("should load custom trust anchors", func() {
				customAnchors := []string{
					". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
				}

				store, err := NewTrustAnchorStore(customAnchors)
				Expect(err).Should(Succeed())
				Expect(store).ShouldNot(BeNil())

				rootAnchors := store.GetRootTrustAnchors()
				Expect(rootAnchors).Should(HaveLen(1))
				Expect(rootAnchors[0].Key.KeyTag()).Should(Equal(uint16(20326))) // KSK-2017
			})

			It("should reject invalid DNSKEY format", func() {
				customAnchors := []string{"invalid DNSKEY format"}

				store, err := NewTrustAnchorStore(customAnchors)
				Expect(err).Should(HaveOccurred())
				Expect(store).Should(BeNil())
			})

			It("should reject non-KSK anchors (SEP flag not set)", func() {
				// ZSK with flags 256 (not 257)
				customAnchors := []string{
					". 172800 IN DNSKEY 256 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
				}

				store, err := NewTrustAnchorStore(customAnchors)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("not a KSK"))
				Expect(store).Should(BeNil())
			})

			It("should reject non-DNSKEY records", func() {
				customAnchors := []string{
					"example.com. 300 IN A 192.0.2.1",
				}

				store, err := NewTrustAnchorStore(customAnchors)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(ContainSubstring("not a DNSKEY"))
				Expect(store).Should(BeNil())
			})
		})
	})

	Describe("GetTrustAnchors", func() {
		var store *TrustAnchorStore

		BeforeEach(func() {
			var err error
			store, err = NewTrustAnchorStore(nil)
			Expect(err).Should(Succeed())
		})

		It("should return root trust anchors", func() {
			anchors := store.GetTrustAnchors(".")
			Expect(anchors).ShouldNot(BeEmpty())
		})

		It("should normalize domain names", func() {
			// Add custom anchor for example.com
			customStore, err := NewTrustAnchorStore([]string{
				"example.com. 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
			})
			Expect(err).Should(Succeed())

			// Test various forms of the same domain
			anchors1 := customStore.GetTrustAnchors("example.com")
			anchors2 := customStore.GetTrustAnchors("example.com.")
			anchors3 := customStore.GetTrustAnchors("EXAMPLE.COM.")

			Expect(anchors1).Should(HaveLen(len(anchors2)))
			Expect(anchors1).Should(HaveLen(len(anchors3)))
		})

		It("should return empty slice for domains without anchors", func() {
			anchors := store.GetTrustAnchors("example.com.")
			Expect(anchors).Should(BeEmpty())
		})
	})

	Describe("HasTrustAnchor", func() {
		var store *TrustAnchorStore

		BeforeEach(func() {
			var err error
			store, err = NewTrustAnchorStore(nil)
			Expect(err).Should(Succeed())
		})

		It("should return true for root zone", func() {
			Expect(store.HasTrustAnchor(".")).Should(BeTrue())
		})

		It("should return false for domains without anchors", func() {
			Expect(store.HasTrustAnchor("example.com.")).Should(BeFalse())
		})

		It("should normalize domain names", func() {
			Expect(store.HasTrustAnchor(".")).Should(Equal(store.HasTrustAnchor(".")))
		})
	})

	Describe("AddTrustAnchor", func() {
		var store *TrustAnchorStore

		BeforeEach(func() {
			store = &TrustAnchorStore{
				anchors: make(map[string][]*TrustAnchor),
			}
		})

		It("should add valid DNSKEY with SEP flag", func() {
			anchorStr := ". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="

			err := store.AddTrustAnchor(anchorStr)
			Expect(err).Should(Succeed())
			Expect(store.HasTrustAnchor(".")).Should(BeTrue())
		})

		It("should reject malformed anchor strings", func() {
			err := store.AddTrustAnchor("malformed")
			Expect(err).Should(HaveOccurred())
		})

		It("should allow multiple anchors for the same domain", func() {
			anchor1 := ". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="
			anchor2 := ". 172800 IN DNSKEY 257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUEA yffKC73PYc="

			err := store.AddTrustAnchor(anchor1)
			Expect(err).Should(Succeed())
			err = store.AddTrustAnchor(anchor2)
			Expect(err).Should(Succeed())

			anchors := store.GetRootTrustAnchors()
			Expect(anchors).Should(HaveLen(2))
		})
	})

	Describe("GetRootTrustAnchors", func() {
		It("should return root trust anchors", func() {
			store, err := NewTrustAnchorStore(nil)
			Expect(err).Should(Succeed())

			rootAnchors := store.GetRootTrustAnchors()
			Expect(rootAnchors).ShouldNot(BeEmpty())

			// Verify all returned anchors are for root zone
			for _, anchor := range rootAnchors {
				Expect(anchor.Key.Header().Name).Should(Equal("."))
			}
		})
	})

	Describe("getDefaultRootTrustAnchors", func() {
		It("should return non-empty list", func() {
			anchors := getDefaultRootTrustAnchors()
			Expect(anchors).ShouldNot(BeEmpty())
		})

		It("should return valid DNSKEY records", func() {
			anchors := getDefaultRootTrustAnchors()
			for _, anchorStr := range anchors {
				Expect(anchorStr).Should(ContainSubstring("IN DNSKEY"))
				Expect(anchorStr).Should(ContainSubstring("257")) // KSK flag
			}
		})
	})
})
