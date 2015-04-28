package yara

/*
#include <stdio.h>
#include <stdio.h>
#include <yara.h>
#include "cgoyara.h"
*/
import "C"

import (
	"io"
	"unsafe"
)

var callback = (C.YR_CALLBACK_FUNC)(unsafe.Pointer(C.yr_callback))

//export cgo_stream_read
func cgo_stream_read(ptr unsafe.Pointer, size C.size_t, count C.size_t, prw unsafe.Pointer) C.size_t {
	r := *(*io.Reader)(prw)

	buffer := make([]byte, int(size))
	n, err := r.Read(buffer)
	if err != nil {
		return 0
	}

	C.memcpy(ptr, (unsafe.Pointer)(&buffer[0]), C.size_t(n))
	return 1
}

//export cgo_stream_write
func cgo_stream_write(ptr unsafe.Pointer, size C.size_t, count C.size_t, prw unsafe.Pointer) C.size_t {
	w := *(*io.Writer)(prw)

	buffer := make([]byte, int(size))
	C.memcpy((unsafe.Pointer)(&buffer[0]), ptr, size)

	_, err := w.Write(buffer)
	if err != nil {
		return 0
	}

	return 1
}
