package release

import "fmt"

// Step names the stage of the pipeline that refused.
type Step string

// The steps a Refusal can name.
const (
	StepPreflight Step = "preflight"
	StepResolve   Step = "resolve"
	StepDownload  Step = "download"
	StepChecksum  Step = "checksum"
	StepExtract   Step = "extract"
	StepMachO     Step = "macho"
	StepAttest    Step = "attest"
)

// Refusal reports input the tool will not sign: the release, an asset, an
// archive, a binary or an attestation that is not exactly what was expected.
// A command that could not run at all is a plain wrapped error instead.
type Refusal struct {
	Step   Step
	Reason string
}

// Error names the step and the reason.
func (e *Refusal) Error() string {
	return fmt.Sprintf("refused at %s: %s", e.Step, e.Reason)
}

func refuse(step Step, format string, args ...any) error {
	return &Refusal{Step: step, Reason: fmt.Sprintf(format, args...)}
}
