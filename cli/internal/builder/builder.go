package builder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"

	"github.com/skillledger/skillledger/internal/canon"
	"github.com/skillledger/skillledger/internal/manifest"
	"github.com/skillledger/skillledger/internal/scanner"
)

// BuildResult holds the outputs of a successful build.
type BuildResult struct {
	// ArtifactPath is the full path to the output .skillledger.tar.gz file.
	ArtifactPath string
	// LockfilePath is the full path to the generated skill-lock.json.
	LockfilePath string
	// SHA256 is the hex digest of the artifact.
	SHA256 string
	// Filename is the content-addressed artifact filename.
	Filename string
}

// Builder orchestrates the deterministic build pipeline:
// manifest -> collect -> canonicalize -> archive -> hash -> lockfile.
type Builder struct {
	fs    afero.Fs
	epoch time.Time
}

// BuilderOption configures a Builder.
type BuilderOption func(*Builder)

// WithEpoch overrides the build epoch (primarily for testing).
func WithEpoch(t time.Time) BuilderOption {
	return func(b *Builder) {
		b.epoch = t
	}
}

// WithFs overrides the filesystem implementation (primarily for testing).
func WithFs(fs afero.Fs) BuilderOption {
	return func(b *Builder) {
		b.fs = fs
	}
}

// NewBuilder creates a Builder with sensible defaults and applies any options.
func NewBuilder(opts ...BuilderOption) *Builder {
	b := &Builder{
		fs:    afero.NewOsFs(),
		epoch: ResolveEpoch(),
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// Build executes the full deterministic build pipeline on sourceDir and writes
// the content-addressed artifact to outputDir. It returns a BuildResult or an
// error if any pipeline stage fails.
func (b *Builder) Build(sourceDir, outputDir string) (*BuildResult, error) {
	// Step 1: Load and validate manifest.
	manifestPath := filepath.Join(sourceDir, "skillledger.yaml")
	yamlBytes, err := afero.ReadFile(b.fs, manifestPath)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}

	m, validationErrors, err := manifest.ParseAndValidate(yamlBytes)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	if len(validationErrors) > 0 {
		return nil, fmt.Errorf("manifest validation: %d errors: %s", len(validationErrors), validationErrors[0].Message)
	}
	log.Debug().Str("path", manifestPath).Msg("Manifest loaded")

	// Step 2: Collect source files.
	files, err := NewCollector(b.fs).Collect(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("collecting files: %w", err)
	}
	log.Debug().Int("files", len(files)).Msg("Source files collected")

	// Step 3: Canonicalize manifest for embedding.
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing manifest: %w", err)
	}
	canonicalManifest, err := canon.Canonicalize(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing manifest: %w", err)
	}

	// Step 4: Create deterministic archive.
	var buf bytes.Buffer
	if err := CreateDeterministicArchive(&buf, canonicalManifest, files, b.epoch); err != nil {
		return nil, fmt.Errorf("creating archive: %w", err)
	}
	artifactBytes := buf.Bytes()
	log.Debug().Int("bytes", len(artifactBytes)).Msg("Archive created")

	// Step 5: Hash and compute content-addressed name.
	hash := scanner.HashBytes(artifactBytes)
	filename := ContentAddressedName(m.ID, m.Version, artifactBytes)
	log.Debug().Str("sha256", hash[:12]).Str("filename", filename).Msg("Artifact hashed")

	// Step 6: Write artifact to output directory.
	if err := b.fs.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}
	outputPath := filepath.Join(outputDir, filename)
	if err := afero.WriteFile(b.fs, outputPath, artifactBytes, 0644); err != nil {
		return nil, fmt.Errorf("writing artifact: %w", err)
	}

	// Step 7: Write lockfile to source directory.
	lockPath := filepath.Join(sourceDir, "skill-lock.json")
	lf := &Lockfile{
		SkillLedger:    1,
		ArtifactID:     m.ID,
		Version:        m.Version,
		SHA256:         hash,
		ContentAddress: filename,
		BuiltAt:        b.epoch.UTC().Format(time.RFC3339),
		Source: LockfileSource{
			Repository: m.Source.Repository,
			Ref:        m.Source.Ref,
			Directory:  m.Source.Directory,
		},
	}
	if err := WriteLockfile(lockPath, lf); err != nil {
		return nil, fmt.Errorf("writing lockfile: %w", err)
	}

	return &BuildResult{
		ArtifactPath: outputPath,
		LockfilePath: lockPath,
		SHA256:       hash,
		Filename:     filename,
	}, nil
}
