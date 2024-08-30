package util

// ConvertEach implements the functional map operation, under a different
// name to avoid confusion with Go's map type.
func ConvertEach[T, U any](slice []T, convert func(T) U) []U {
	if slice == nil {
		return nil
	}

	res := make([]U, 0, len(slice))

	for _, t := range slice {
		u := convert(t)

		res = append(res, u)
	}

	return res
}

// ConcatSlices returns a new slice with contents of all the inputs concatenated.
func ConcatSlices[T any](slices ...[]T) []T {
	// Allocation is usually the bottleneck, so do it all at once
	totalLen := 0

	for _, slice := range slices {
		totalLen += len(slice)
	}

	res := make([]T, 0, totalLen)

	for _, slice := range slices {
		res = append(res, slice...)
	}

	return res
}
