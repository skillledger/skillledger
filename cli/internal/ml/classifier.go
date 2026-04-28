package ml

import "errors"

// Classifier scores text for prompt injection probability.
type Classifier interface {
	// Classify returns injection probability [0.0, 1.0] and any error.
	// Returns ErrMLDisabled when built with -tags no_ml.
	Classify(text string) (float64, error)
	// Close releases model resources (ONNX session, tokenizer).
	Close() error
}

// ErrMLDisabled is returned by the stub classifier when ML is compiled out.
var ErrMLDisabled = errors.New("ML classifier disabled (built with -tags no_ml)")

// ModelInfo describes a downloaded ML model for the model manager.
type ModelInfo struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	ModelPath     string `json:"model_path"`
	TokenizerPath string `json:"tokenizer_path"`
	OrtLibPath    string `json:"ort_lib_path"`
	SHA256        string `json:"sha256"`
}

// DefaultModelName is the model identifier for the prompt injection classifier.
const DefaultModelName = "deberta-v3-prompt-injection-v2"

// DefaultMaxSeqLen is the maximum token sequence length for the DeBERTa model.
const DefaultMaxSeqLen = 512
