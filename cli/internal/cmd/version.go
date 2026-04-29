package cmd

// version is set at build time via:
//
//	go build -ldflags "-X github.com/skillledger/skillledger/internal/cmd.version=$(cat VERSION)"
var version = "dev"

func init() {
	rootCmd.Version = version
}
