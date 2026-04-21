package runtime

// RuntimeRegistry holds all registered runtime adapters.
type RuntimeRegistry struct {
	adapters []RuntimeAdapter
}

// NewRuntimeRegistry creates a RuntimeRegistry with the given adapters.
func NewRuntimeRegistry(adapters ...RuntimeAdapter) *RuntimeRegistry {
	return &RuntimeRegistry{adapters: adapters}
}

// DefaultRuntimeRegistry returns a registry with all standard runtime adapters.
func DefaultRuntimeRegistry() *RuntimeRegistry {
	return NewRuntimeRegistry(
		&HTTPProxyAdapter{},
		&MCPStdioAdapter{},
		&ShimAdapter{},
	)
}

// ForKind looks up an adapter by its kind string.
func (r *RuntimeRegistry) ForKind(kind string) (RuntimeAdapter, bool) {
	for _, a := range r.adapters {
		if a.Kind() == kind {
			return a, true
		}
	}
	return nil, false
}

// All returns all registered adapters.
func (r *RuntimeRegistry) All() []RuntimeAdapter {
	return r.adapters
}
