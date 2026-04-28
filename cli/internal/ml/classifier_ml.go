//go:build !no_ml

package ml

import (
	"fmt"
	"math"
	"sync"

	"github.com/daulet/tokenizers"
	ort "github.com/yalue/onnxruntime_go"
)

var (
	ortInitOnce sync.Once
	ortInitErr  error
)

type debertaClassifier struct {
	modelPath     string
	tokenizerPath string
	ortLibPath    string

	mu        sync.Mutex
	tokenizer *tokenizers.Tokenizer
	session   *ort.AdvancedSession
	inputIDs  *ort.Tensor[int64]
	attMask   *ort.Tensor[int64]
	logits    *ort.Tensor[float32]
	loaded    bool
}

// NewClassifier creates a new DeBERTa ONNX classifier. The model is NOT loaded
// at construction time -- it is loaded lazily on the first Classify call.
// This keeps proxy startup fast (per RESEARCH.md: model is ~100MB).
func NewClassifier(modelPath, tokenizerPath, ortLibPath string) (Classifier, error) {
	return &debertaClassifier{
		modelPath:     modelPath,
		tokenizerPath: tokenizerPath,
		ortLibPath:    ortLibPath,
	}, nil
}

// ensureLoaded lazily initializes the ONNX session and tokenizer on first use.
func (c *debertaClassifier) ensureLoaded() error {
	if c.loaded {
		return nil
	}

	// Initialize ORT shared library (once per process).
	ortInitOnce.Do(func() {
		ort.SetSharedLibraryPath(c.ortLibPath)
		ortInitErr = ort.InitializeEnvironment()
	})
	if ortInitErr != nil {
		return fmt.Errorf("initialize ONNX environment: %w", ortInitErr)
	}

	// Load tokenizer.
	tk, err := newTokenizer(c.tokenizerPath)
	if err != nil {
		return err
	}
	c.tokenizer = tk

	// Create ONNX session with DeBERTa model.
	// Input shapes: [1, DefaultMaxSeqLen] for both input_ids and attention_mask.
	// Output shape: [1, 2] for binary classification logits.
	inputShape := ort.NewShape(1, int64(DefaultMaxSeqLen))
	outputShape := ort.NewShape(1, 2)

	inputIDs, err := ort.NewEmptyTensor[int64](inputShape)
	if err != nil {
		return fmt.Errorf("create input_ids tensor: %w", err)
	}
	c.inputIDs = inputIDs

	attMask, err := ort.NewEmptyTensor[int64](inputShape)
	if err != nil {
		return fmt.Errorf("create attention_mask tensor: %w", err)
	}
	c.attMask = attMask

	logits, err := ort.NewEmptyTensor[float32](outputShape)
	if err != nil {
		return fmt.Errorf("create logits tensor: %w", err)
	}
	c.logits = logits

	session, err := ort.NewAdvancedSession(
		c.modelPath,
		[]string{"input_ids", "attention_mask"},
		[]string{"logits"},
		[]ort.Value{inputIDs, attMask},
		[]ort.Value{logits},
		nil, // default session options
	)
	if err != nil {
		return fmt.Errorf("create ONNX session: %w", err)
	}

	c.session = session
	c.loaded = true
	return nil
}

// Classify returns the injection probability [0.0, 1.0] for the given text.
// Thread-safe: multiple goroutines may call Classify concurrently.
func (c *debertaClassifier) Classify(text string) (float64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureLoaded(); err != nil {
		return 0, fmt.Errorf("load model: %w", err)
	}

	// Tokenize input text.
	tokens, err := tokenize(c.tokenizer, text, DefaultMaxSeqLen)
	if err != nil {
		return 0, err
	}

	// Copy token data into session input tensors.
	copy(c.inputIDs.GetData(), tokens.InputIDs)
	copy(c.attMask.GetData(), tokens.AttentionMask)

	// Run inference.
	if err := c.session.Run(); err != nil {
		return 0, fmt.Errorf("ONNX inference: %w", err)
	}

	// Extract logits and apply softmax.
	logitsData := c.logits.GetData()
	if len(logitsData) < 2 {
		return 0, fmt.Errorf("unexpected logits length: %d", len(logitsData))
	}

	// Softmax: P(injection) = exp(logits[1]) / (exp(logits[0]) + exp(logits[1]))
	// Using numerically stable form (subtract max before exp).
	maxLogit := math.Max(float64(logitsData[0]), float64(logitsData[1]))
	exp0 := math.Exp(float64(logitsData[0]) - maxLogit)
	exp1 := math.Exp(float64(logitsData[1]) - maxLogit)
	injectionProb := exp1 / (exp0 + exp1)

	return injectionProb, nil
}

// Close releases all model resources (ONNX session, tensors, tokenizer).
func (c *debertaClassifier) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != nil {
		if err := c.session.Destroy(); err != nil {
			return fmt.Errorf("destroy ONNX session: %w", err)
		}
		c.session = nil
	}
	if c.inputIDs != nil {
		c.inputIDs.Destroy()
		c.inputIDs = nil
	}
	if c.attMask != nil {
		c.attMask.Destroy()
		c.attMask = nil
	}
	if c.logits != nil {
		c.logits.Destroy()
		c.logits = nil
	}
	if c.tokenizer != nil {
		c.tokenizer.Close()
		c.tokenizer = nil
	}
	c.loaded = false

	return nil
}
