// +build bleeding

package yara

/*
#include <stdio.h>
#include <yara.h>
#include "cgoyara.h"
*/
import "C"

import (
	"io"
	"io/ioutil"
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

// Scan should be avoided for now.
func (r *Rules) Scan(reader io.Reader, fn Callback) error {
	data, err := ioutil.ReadAll(reader)
	if err != nil {
		return err
	}

	return r.ScanMemory(data, fn)
}

func readStream(r io.Reader) *C.YR_STREAM {
	stream := new(C.YR_STREAM)
	stream.user_data = unsafe.Pointer(&r)
	stream.read = (C.YR_STREAM_READ_FUNC)(C.stream_read)
	stream.write = (C.YR_STREAM_WRITE_FUNC)(C.stream_write)
	return stream
}

func writeStream(w io.Writer) *C.YR_STREAM {
	stream := new(C.YR_STREAM)
	stream.user_data = unsafe.Pointer(&w)
	stream.read = (C.YR_STREAM_READ_FUNC)(C.stream_read)
	stream.write = (C.YR_STREAM_WRITE_FUNC)(C.stream_write)
	return stream
}
