package arp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadFile(t *testing.T) {
	content := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.100    0x1         0x2         11:22:33:44:55:66     *        eth0
10.0.0.1         0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.50     0x1         0x2         de:ad:be:ef:00:01     *        wlan0
`
	f := filepath.Join(t.TempDir(), "arp")
	require.NoError(t, os.WriteFile(f, []byte(content), 0644))

	entries, err := ReadFile(f)
	require.NoError(t, err)

	assert.Len(t, entries, 3)

	assert.Equal(t, Entry{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:ff", Device: "eth0"}, entries[0])
	assert.Equal(t, Entry{IP: "192.168.1.100", MAC: "11:22:33:44:55:66", Device: "eth0"}, entries[1])
	assert.Equal(t, Entry{IP: "192.168.1.50", MAC: "de:ad:be:ef:00:01", Device: "wlan0"}, entries[2])
}

func TestReadFile_SkipsIncomplete(t *testing.T) {
	content := `IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1         0x1         0x0         00:00:00:00:00:00     *        eth0
10.0.0.2         0x1         0x2         00:00:00:00:00:00     *        eth0
`
	f := filepath.Join(t.TempDir(), "arp")
	require.NoError(t, os.WriteFile(f, []byte(content), 0644))

	entries, err := ReadFile(f)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestReadFile_Missing(t *testing.T) {
	entries, err := ReadFile("/nonexistent/path")
	require.NoError(t, err)
	assert.Nil(t, entries)
}

func TestReadFile_Empty(t *testing.T) {
	content := `IP address       HW type     Flags       HW address            Mask     Device
`
	f := filepath.Join(t.TempDir(), "arp")
	require.NoError(t, os.WriteFile(f, []byte(content), 0644))

	entries, err := ReadFile(f)
	require.NoError(t, err)
	assert.Empty(t, entries)
}
