package ingress

import "net/http"

// RawUpload is the original station request for fan-out replay.
type RawUpload struct {
	Method   string
	Path     string
	RawQuery string
	Header   http.Header
	Body     []byte
	Host     string
}
