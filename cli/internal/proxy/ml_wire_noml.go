//go:build no_ml

package proxy

import (
	"io"

	"github.com/rs/zerolog"
)

// tryLoadMLClassifier is the no_ml build stub. It always returns nil,
// meaning the proxy operates in heuristic-only mode for injection detection.
//
// This file is compiled only when the no_ml build tag is set. It avoids
// importing the ml package, which would pull in ONNX Runtime and tokenizer
// dependencies that are unavailable in constrained environments.
func tryLoadMLClassifier(_ string, _ *InjectionScanner, logger zerolog.Logger) io.Closer {
	logger.Debug().Msg("ML classifier disabled (no_ml build)")
	return nil
}
