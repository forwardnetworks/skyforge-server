package skyforge

func ptr[T any](v T) *T {
	return &v
}
