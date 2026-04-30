package cmd

import "time"

// version is set at build time via:
//
//	go build -ldflags "-X github.com/skillledger/skillledger/internal/cmd.version=$(cat VERSION)"
var version = "dev"

// buildTime is set at build time via:
//
//	go build -ldflags "-X github.com/skillledger/skillledger/internal/cmd.buildTime=2026-05-01T10:00:00Z"
var buildTime = ""

// BuildTime parses buildTime as RFC3339 and returns the result.
// On parse failure (including empty string when running `go run`), returns
// time.Time{} (zero value), which means "always prefer cache" -- the safe
// default for development.
func BuildTime() time.Time {
	t, err := time.Parse(time.RFC3339, buildTime)
	if err != nil {
		return time.Time{}
	}
	return t
}

func init() {
	rootCmd.Version = version
}
