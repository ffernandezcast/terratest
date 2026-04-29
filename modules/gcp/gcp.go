// Package gcp allows interaction with Google Cloud Platform resources.
package gcp

import (
	"google.golang.org/api/option"
)

func withOptions() (opts []option.ClientOption) {
	v, ok := getStaticTokenSource()
	if ok {
		opts = append(opts, option.WithTokenSource(v))
	}

	return
}
