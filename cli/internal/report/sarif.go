package report

import (
	"io"

	"github.com/owenrumney/go-sarif/v3/pkg/report"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/skillledger/skillledger/internal/scanner"
)

// GenerateSARIF writes a SARIF 2.1.0 report to w from scan results.
// Compatible with GitHub Code Scanning upload requirements.
func GenerateSARIF(w io.Writer, results []scanner.ScanResult) error {
	r := report.NewV210Report()

	run := sarif.NewRunWithInformationURI("skillledger", "https://skillledger.dev")

	// Register IOC rule
	run.AddRule("SL001").
		WithDescription("Skill matches known-compromised IOC hash").
		WithHelpURI("https://skillledger.dev/docs/ioc")

	// Register YARA rule
	run.AddRule("SL002").
		WithDescription("Skill matches YARA detection rule").
		WithHelpURI("https://skillledger.dev/docs/yara")

	for _, res := range results {
		if res.IOCMatch != nil {
			run.CreateResultForRule("SL001").
				WithLevel("error").
				WithMessage(sarif.NewTextMessage(res.IOCMatch.Description)).
				AddLocation(
					sarif.NewLocationWithPhysicalLocation(
						sarif.NewPhysicalLocation().
							WithArtifactLocation(
								sarif.NewSimpleArtifactLocation(res.Skill.Path),
							).WithRegion(
							sarif.NewSimpleRegion(1, 1),
						),
					),
				)
		}
		for _, ym := range res.YARAMatches {
			run.CreateResultForRule("SL002").
				WithLevel("warning").
				WithMessage(sarif.NewTextMessage(ym.RuleName)).
				AddLocation(
					sarif.NewLocationWithPhysicalLocation(
						sarif.NewPhysicalLocation().
							WithArtifactLocation(
								sarif.NewSimpleArtifactLocation(res.Skill.Path),
							).WithRegion(
							sarif.NewSimpleRegion(1, 1),
						),
					),
				)
		}
	}

	r.AddRun(run)
	return r.PrettyWrite(w)
}
