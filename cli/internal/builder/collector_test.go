package builder_test

import (
	"os"
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

func TestCollector_SkipsSymlinks(t *testing.T) {
	// Use OsFs on a real temp directory because MemMapFs doesn't support symlinks.
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	require.NoError(t, os.MkdirAll(srcDir, 0o755))

	// Create a real file.
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "real.txt"), []byte("real"), 0o644))

	// Create a target file outside the source tree that the symlink points to.
	targetFile := filepath.Join(tmpDir, "secret.txt")
	require.NoError(t, os.WriteFile(targetFile, []byte("secret"), 0o644))

	// Create a symlink inside the source tree pointing to the external target.
	require.NoError(t, os.Symlink(targetFile, filepath.Join(srcDir, "link.txt")))

	fs := afero.NewOsFs()
	c := builder.NewCollector(fs)
	entries, err := c.Collect(srcDir)
	require.NoError(t, err)

	// Only the real file should be collected; the symlink must be skipped.
	require.Len(t, entries, 1)
	assert.Equal(t, "real.txt", entries[0].RelPath)
	assert.Equal(t, "real", string(entries[0].Content))
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
