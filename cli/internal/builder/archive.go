package builder

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/skillledger/skillledger/internal/scanner"
)

// ResolveEpoch returns the build timestamp. If SOURCE_DATE_EPOCH is set it is
// parsed as a Unix timestamp; otherwise Unix epoch (0) is used.
func ResolveEpoch() time.Time {
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		secs, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			return time.Unix(secs, 0).UTC()
		}
	}
	return time.Unix(0, 0).UTC()
}

// CreateDeterministicArchive writes a tar.gz archive to w containing the
// canonical manifest JSON as the first entry followed by all file entries.
// Every tar header uses USTAR format with zeroed UID/GID, fixed 0644 mode,
// and the supplied epoch as ModTime. The gzip OS byte is set to 0xFF
// (unknown) to prevent platform-dependent variation.
func CreateDeterministicArchive(w io.Writer, manifestJSON []byte, files []FileEntry, epoch time.Time) error {
	gz, err := gzip.NewWriterLevel(w, gzip.DefaultCompression)
	if err != nil {
		return fmt.Errorf("create gzip writer: %w", err)
	}
	// RFC 1952 section 2.3: OS byte 0xFF = unknown, ensuring determinism.
	gz.OS = 0xFF

	tw := tar.NewWriter(gz)

	// Write canonical manifest as first entry.
	if err := writeEntry(tw, "skillledger.json", manifestJSON, epoch); err != nil {
		return fmt.Errorf("write manifest entry: %w", err)
	}

	// Write each collected file in order (already sorted by Collector).
	for _, f := range files {
		if err := writeEntry(tw, f.RelPath, f.Content, epoch); err != nil {
			return fmt.Errorf("write entry %s: %w", f.RelPath, err)
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar writer: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip writer: %w", err)
	}

	return nil
}

// writeEntry adds a single file entry to the tar writer with normalized metadata.
func writeEntry(tw *tar.Writer, name string, content []byte, epoch time.Time) error {
	hdr := &tar.Header{
		Name:    name,
		Size:    int64(len(content)),
		Mode:    0644,
		Uid:     0,
		Gid:     0,
		Uname:   "",
		Gname:   "",
		ModTime: epoch,
		Format:  tar.FormatUSTAR,
	}

	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(content); err != nil {
		return err
	}
	return nil
}

// ContentAddressedName returns an artifact filename that embeds the first 12
// hex characters of the SHA-256 digest of artifactBytes.
func ContentAddressedName(id, version string, artifactBytes []byte) string {
	hash := scanner.HashBytes(artifactBytes)
	shortHash := hash[:12]
	return fmt.Sprintf("%s-%s-%s.skillledger.tar.gz", id, version, shortHash)
}
