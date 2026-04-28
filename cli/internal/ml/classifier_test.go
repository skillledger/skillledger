package ml

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrMLDisabled_Exists(t *testing.T) {
	assert.NotNil(t, ErrMLDisabled)
	assert.True(t, strings.Contains(ErrMLDisabled.Error(), "no_ml"),
		"ErrMLDisabled message should reference the no_ml build tag")
}

func TestErrMLDisabled_ErrorMessage(t *testing.T) {
	msg := ErrMLDisabled.Error()
	assert.Contains(t, msg, "ML classifier disabled")
	assert.Contains(t, msg, "no_ml")
}

func TestDefaultModelName_Constant(t *testing.T) {
	assert.Equal(t, "deberta-v3-prompt-injection-v2", DefaultModelName)
}

func TestDefaultMaxSeqLen_Constant(t *testing.T) {
	assert.Equal(t, 512, DefaultMaxSeqLen)
}

func TestModelInfo_Fields(t *testing.T) {
	info := ModelInfo{
		Name:          "test-model",
		Version:       "1.0.0",
		ModelPath:     "/path/to/model.onnx",
		TokenizerPath: "/path/to/tokenizer.json",
		OrtLibPath:    "/path/to/libort.dylib",
		SHA256:        "abc123",
	}

	assert.Equal(t, "test-model", info.Name)
	assert.Equal(t, "1.0.0", info.Version)
	assert.Equal(t, "/path/to/model.onnx", info.ModelPath)
	assert.Equal(t, "/path/to/tokenizer.json", info.TokenizerPath)
	assert.Equal(t, "/path/to/libort.dylib", info.OrtLibPath)
	assert.Equal(t, "abc123", info.SHA256)
}
