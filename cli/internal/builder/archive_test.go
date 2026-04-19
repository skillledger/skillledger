package builder_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"regexp"
	"testing"
	"time"

	"github.com/skillledger/skillledger/internal/builder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleFiles() []builder.FileEntry {
	return []builder.FileEntry{
		{RelPath: "a.txt", Content: []byte("aaa")},
		{RelPath: "b.txt", Content: []byte("bbb")},
		{RelPath: "c.txt", Content: []byte("ccc")},
	}
}

func sampleManifest() []byte {
	return []byte(`{"id":"test-skill","version":"1.0.0","skillledger":1}`)
}

func buildArchive(t *testing.T, epoch time.Time) []byte {
	t.Helper()
	var buf bytes.Buffer
	err := builder.CreateDeterministicArchive(&buf, sampleManifest(), sampleFiles(), epoch)
	require.NoError(t, err)
	return buf.Bytes()
}

func TestArchive_Deterministic(t *testing.T) {
	epoch := time.Unix(1700000000, 0).UTC()
	buf1 := buildArchive(t, epoch)
	buf2 := buildArchive(t, epoch)
	assert.True(t, bytes.Equal(buf1, buf2), "archives must be byte-identical for same inputs")
}

func TestArchive_ManifestFirstEntry(t *testing.T) {
	data := buildArchive(t, time.Unix(1700000000, 0).UTC())
	gr, err := gzip.NewReader(bytes.NewReader(data))
	require.NoError(t, err)
	defer gr.Close()

	tr := tar.NewReader(gr)
	hdr, err := tr.Next()
	require.NoError(t, err)

	assert.Equal(t, "skillledger.json", hdr.Name)
	assert.Equal(t, int64(0), int64(hdr.Uid))
	assert.Equal(t, int64(0), int64(hdr.Gid))
	assert.Equal(t, int64(0644), hdr.Mode)
	assert.Equal(t, tar.FormatUSTAR, hdr.Format)
}

func TestArchive_ZeroedMetadata(t *testing.T) {
	data := buildArchive(t, time.Unix(1700000000, 0).UTC())
	gr, err := gzip.NewReader(bytes.NewReader(data))
	require.NoError(t, err)
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		assert.Equal(t, 0, hdr.Uid, "Uid must be 0 for %s", hdr.Name)
		assert.Equal(t, 0, hdr.Gid, "Gid must be 0 for %s", hdr.Name)
		assert.Equal(t, "", hdr.Uname, "Uname must be empty for %s", hdr.Name)
		assert.Equal(t, "", hdr.Gname, "Gname must be empty for %s", hdr.Name)
		assert.Equal(t, int64(0644), hdr.Mode, "Mode must be 0644 for %s", hdr.Name)
	}
}

func TestArchive_ClampedTimestamp(t *testing.T) {
	epoch := time.Unix(1234567890, 0).UTC()
	data := buildArchive(t, epoch)

	gr, err := gzip.NewReader(bytes.NewReader(data))
	require.NoError(t, err)
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		assert.True(t, hdr.ModTime.Equal(epoch),
			"ModTime for %s should be %v, got %v", hdr.Name, epoch, hdr.ModTime)
	}
}

func TestArchive_GzipOSByte(t *testing.T) {
	data := buildArchive(t, time.Unix(1700000000, 0).UTC())
	// RFC 1952: byte at index 9 is the OS field.
	require.True(t, len(data) > 9, "archive too small")
	assert.Equal(t, byte(0xFF), data[9], "gzip OS byte must be 0xFF (unknown)")
}

func TestContentAddressedName(t *testing.T) {
	name := builder.ContentAddressedName("my-skill", "1.0.0", []byte("test data"))
	pattern := `^my-skill-1\.0\.0-[a-f0-9]{12}\.skillledger\.tar\.gz$`
	assert.Regexp(t, regexp.MustCompile(pattern), name)
}

func TestResolveEpoch_EnvVar(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	got := builder.ResolveEpoch()
	assert.True(t, got.Equal(time.Unix(1700000000, 0).UTC()))
}

func TestResolveEpoch_Fallback(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "")
	got := builder.ResolveEpoch()
	assert.True(t, got.Equal(time.Unix(0, 0).UTC()))
}
