//go:build no_ml

package ml

// tokenizeResult holds tokenizer output.
type tokenizeResult struct {
	InputIDs      []int64
	AttentionMask []int64
}

// tokenize is a stub that returns ErrMLDisabled.
func tokenize(_ interface{}, _ string, _ int) (*tokenizeResult, error) {
	return nil, ErrMLDisabled
}
