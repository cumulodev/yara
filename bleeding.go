// +build bleeding

package yara

// #include <stdio.h>
// #include <yara.h>
// #include "cgo.h"
import "C"

import (
	"io"
	"unsafe"
)

func LoadFromReader(r io.Reader) (*Rules, error) {
	var handle *C.YR_RULES
	code := C.yr_rules_load_stream(readStream(r), &handle)
	if code != C.ERROR_SUCCESS {
		return nil, newError(code)
	}

	return &Rules{handle}, nil
}

func (r *Rules) Write(w io.Writer) error {
	code := C.yr_rules_save_stream(r.handle, writeStream(w))
	if code != C.ERROR_SUCCESS {
		return newError(code)
	}

	return nil
}

func readStream(r io.Reader) *C.YR_STREAM {
	stream := new(C.YR_STREAM)
	stream.user_data = unsafe.Pointer(&r)
	stream.read = (C.YR_STREAM_READ_FUNC)(C.stream_read)
	return stream
}

func writeStream(w io.Writer) *C.YR_STREAM {
	stream := new(C.YR_STREAM)
	stream.user_data = unsafe.Pointer(&w)
	stream.write = (C.YR_STREAM_WRITE_FUNC)(C.stream_write)
	return stream
}
