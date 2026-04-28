//go:build no_ml

package ml

type stubClassifier struct{}

// NewClassifier returns a stub classifier when built with -tags no_ml.
// The stub always returns (0, ErrMLDisabled) from Classify.
func NewClassifier(modelPath, tokenizerPath, ortLibPath string) (Classifier, error) {
	return &stubClassifier{}, nil
}

func (s *stubClassifier) Classify(_ string) (float64, error) {
	return 0, ErrMLDisabled
}

func (s *stubClassifier) Close() error { return nil }
