package report

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/owenrumney/go-sarif/v3/pkg/report"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/skillledger/skillledger/internal/scanner"
)

// GenerateSARIF writes a SARIF 2.1.0 report to w from scan results.
// Compatible with GitHub Code Scanning upload requirements.
// Rules include shortDescription, fullDescription, help, and helpURI fields.
// Results include partialFingerprints for deduplication.
func GenerateSARIF(w io.Writer, results []scanner.ScanResult) error {
	r := report.NewV210Report()

	run := sarif.NewRunWithInformationURI("skillledger", "https://skillledger.in")

	// Register IOC rule with all GitHub-required fields.
	run.AddRule("SL001").
		WithShortDescription(sarif.NewMultiformatMessageString().WithText("Skill matches known-compromised IOC hash")).
		WithFullDescription(sarif.NewMultiformatMessageString().WithText("The skill artifact SHA-256 hash matches a known indicator of compromise from the IOC database. This skill should not be installed or used.")).
		WithHelp(sarif.NewMultiformatMessageString().WithText("Run 'skillledger audit' for full IOC details. See https://skillledger.in/docs/ioc for the IOC database format.")).
		WithHelpURI("https://skillledger.in/docs/ioc")

	// Register YARA rule with all GitHub-required fields.
	run.AddRule("SL002").
		WithShortDescription(sarif.NewMultiformatMessageString().WithText("Skill matches YARA detection rule")).
		WithFullDescription(sarif.NewMultiformatMessageString().WithText("The skill artifact matched a YARA detection rule during audit scanning. Review the matched rule and skill contents.")).
		WithHelp(sarif.NewMultiformatMessageString().WithText("Custom YARA rules can be placed in the rules directory. See https://skillledger.in/docs/yara for rule format.")).
		WithHelpURI("https://skillledger.in/docs/yara")

	for _, res := range results {
		if res.IOCMatch != nil {
			fp := fmt.Sprintf("%x", sha256.Sum256([]byte(res.Skill.ID+res.IOCMatch.SHA256)))
			run.CreateResultForRule("SL001").
				WithLevel("error").
				WithMessage(sarif.NewTextMessage(res.IOCMatch.Description)).
				WithPartialFingerprints(map[string]string{
					"primaryLocationLineHash": fp,
				}).
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
			fp := fmt.Sprintf("%x", sha256.Sum256([]byte(res.Skill.ID+ym.RuleName)))
			run.CreateResultForRule("SL002").
				WithLevel("warning").
				WithMessage(sarif.NewTextMessage(ym.RuleName)).
				WithPartialFingerprints(map[string]string{
					"primaryLocationLineHash": fp,
				}).
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
