package builder_test

import (
	"path/filepath"
	"testing"

	"github.com/skillledger/skillledger/internal/builder"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeSourceTree creates directories and files inside dir on fs.
func makeSourceTree(t *testing.T, fs afero.Fs, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, fs.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, afero.WriteFile(fs, full, []byte(content), 0o644))
	}
}

func TestCollector_SortedOrder(t *testing.T) {
	fs := afero.NewMemMapFs()
	makeSourceTree(t, fs, "/src", map[string]string{
		"c.txt": "c",
		"a.txt": "a",
		"b.txt": "b",
	})

	c := builder.NewCollector(fs)
	entries, err := c.Collect("/src")
	require.NoError(t, err)
	require.Len(t, entries, 3)
	assert.Equal(t, "a.txt", entries[0].RelPath)
	assert.Equal(t, "b.txt", entries[1].RelPath)
	assert.Equal(t, "c.txt", entries[2].RelPath)
}

func TestCollector_DefaultIgnore(t *testing.T) {
	fs := afero.NewMemMapFs()
	makeSourceTree(t, fs, "/src", map[string]string{
		".git/config":              "gitcfg",
		"node_modules/pkg/index.js": "js",
		"src/main.py":              "py",
	})

	c := builder.NewCollector(fs)
	entries, err := c.Collect("/src")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "src/main.py", entries[0].RelPath)
}

func TestCollector_SkillledgerignoreFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	makeSourceTree(t, fs, "/src", map[string]string{
		".skillledgerignore": "secret.key\n*.log",
		"secret.key":         "shhh",
		"app.log":            "log line",
		"main.py":            "print('hi')",
	})

	c := builder.NewCollector(fs)
	entries, err := c.Collect("/src")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "main.py", entries[0].RelPath)
}

func TestCollector_SubdirectorySorting(t *testing.T) {
	fs := afero.NewMemMapFs()
	makeSourceTree(t, fs, "/src", map[string]string{
		"src/b.go": "b",
		"src/a.go": "a",
		"lib/z.go": "z",
	})

	c := builder.NewCollector(fs)
	entries, err := c.Collect("/src")
	require.NoError(t, err)
	require.Len(t, entries, 3)
	assert.Equal(t, "lib/z.go", entries[0].RelPath)
	assert.Equal(t, "src/a.go", entries[1].RelPath)
	assert.Equal(t, "src/b.go", entries[2].RelPath)
}

func TestCollector_EmptyDir(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/empty", 0o755))

	c := builder.NewCollector(fs)
	entries, err := c.Collect("/empty")
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestCollector_MaxFileSize(t *testing.T) {
	fs := afero.NewMemMapFs()
	// Create a file that exceeds 100 bytes limit.
	bigContent := make([]byte, 200)
	for i := range bigContent {
		bigContent[i] = 'x'
	}
	makeSourceTree(t, fs, "/src", map[string]string{
		"big.txt": string(bigContent),
	})

	c := builder.NewCollector(fs, builder.WithMaxFileSize(100))
	_, err := c.Collect("/src")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds size limit")
}
