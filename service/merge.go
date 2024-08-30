package service

import "errors"

// Merger is a Service that can be merged with another compatible one.
type Merger interface {
	Service

	// Merge returns the result of merging the receiver with the other Service.
	//
	// Neither the receiver, nor the other Service should be used directly after
	// calling this method.
	Merge(other Service) (Merger, error)
}

// MergeAll merges the given services, if they are compatible.
//
// This allows using multiple compatible services with a single listener.
//
// All passed-in services must not be re-used.
func MergeAll(services ...Service) (Service, error) {
	switch len(services) {
	case 0:
		return nil, errors.New("no services given")

	case 1:
		return services[0], nil
	}

	merger, err := firstMerger(services)
	if err != nil {
		return nil, err
	}

	for _, svc := range services {
		if svc == merger {
			continue
		}

		merger, err = merger.Merge(svc)
		if err != nil {
			return nil, err
		}
	}

	return merger, nil
}

func firstMerger(services []Service) (Merger, error) {
	for _, t := range services {
		if svc, ok := t.(Merger); ok {
			return svc, nil
		}
	}

	return nil, errors.New("no merger found")
}
