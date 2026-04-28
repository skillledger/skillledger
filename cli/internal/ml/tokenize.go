//go:build !no_ml

package ml

import (
	"fmt"

	"github.com/daulet/tokenizers"
)

// tokenizeResult holds tokenizer output for the ONNX model.
type tokenizeResult struct {
	InputIDs      []int64
	AttentionMask []int64
}

// newTokenizer loads a HuggingFace tokenizer from a tokenizer.json file.
func newTokenizer(tokenizerPath string) (*tokenizers.Tokenizer, error) {
	tk, err := tokenizers.FromFile(tokenizerPath)
	if err != nil {
		return nil, fmt.Errorf("load tokenizer from %s: %w", tokenizerPath, err)
	}
	return tk, nil
}

// tokenize encodes text into token IDs and attention mask for the model.
// The output is padded/truncated to maxLen for the ONNX model's fixed input shape.
func tokenize(tk *tokenizers.Tokenizer, text string, maxLen int) (*tokenizeResult, error) {
	// Encode with special tokens and request attention mask.
	encoding := tk.EncodeWithOptions(text, true,
		tokenizers.WithReturnAttentionMask(),
	)

	ids := encoding.IDs
	mask := encoding.AttentionMask

	// Truncate to maxLen if needed.
	if len(ids) > maxLen {
		ids = ids[:maxLen]
		mask = mask[:maxLen]
	}

	// Convert uint32 IDs to int64 for ONNX tensor and pad to maxLen.
	inputIDs := make([]int64, maxLen)
	attMask := make([]int64, maxLen)
	for i, id := range ids {
		inputIDs[i] = int64(id)
	}
	for i, m := range mask {
		attMask[i] = int64(m)
	}
	// Remaining positions are zero-padded (already zero from make).

	return &tokenizeResult{
		InputIDs:      inputIDs,
		AttentionMask: attMask,
	}, nil
}
