//go:build !no_ml

package proxy

import (
	"io"

	"github.com/rs/zerolog"
	"github.com/skillledger/skillledger/internal/ml"
)

// tryLoadMLClassifier attempts to create an ML classifier from a downloaded
// model. If the model is not downloaded or loading fails, it returns nil
// (graceful degradation to heuristic-only mode).
//
// This file is compiled only in the default build (without the no_ml tag).
// It imports the ml package which pulls in ONNX Runtime and tokenizer
// dependencies. The parallel file ml_wire_noml.go provides a stub for
// the no_ml build tag.
func tryLoadMLClassifier(baseDir string, injScanner *InjectionScanner, logger zerolog.Logger) io.Closer {
	mm := ml.NewModelManager(baseDir)
	if !mm.IsDownloaded() {
		logger.Debug().Msg("ML model not downloaded -- heuristic-only injection detection")
		return nil
	}

	info := mm.ToModelInfo()
	classifier, err := ml.NewClassifier(info.ModelPath, info.TokenizerPath, info.OrtLibPath)
	if err != nil {
		logger.Warn().Err(err).Msg("failed to load ML classifier -- heuristic-only injection detection")
		return nil
	}

	// Wire classifier into injection scanner.
	injScanner.SetClassifier(classifier)
	logger.Info().
		Str("model", ml.DefaultModelName).
		Msg("ML classifier loaded for injection detection")

	return classifier
}
