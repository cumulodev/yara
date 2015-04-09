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

var callback = (C.YR_CALLBACK_FUNC)(unsafe.Pointer(C.cgo_callback))

//export cgo_callback
func cgo_callback(msg C.int, msg_data unsafe.Pointer, user_data unsafe.Pointer) C.int {
	if msg != C.CALLBACK_MSG_RULE_MATCHING {
		return C.CALLBACK_CONTINUE
	}

	if user_data == nil {
		return C.CALLBACK_ERROR
	}

	rule := NewRule()
	C.translate_rule(unsafe.Pointer(rule), (*C.YR_RULE)(msg_data))

	fn := *(*Callback)(user_data)
	fn(rule)

	return C.CALLBACK_CONTINUE
}

//export cgo_rule_set_identifier
func cgo_rule_set_identifier(ptr unsafe.Pointer, identifier *C.char) {
	rule := (*Rule)(ptr)
	rule.Identifier = C.GoString(identifier)
}

//export cgo_rule_add_tag
func cgo_rule_add_tag(ptr unsafe.Pointer, tag *C.char) {
	rule := (*Rule)(ptr)
	rule.Tags = append(rule.Tags, C.GoString(tag))
}

//export cgo_rule_add_metadata
func cgo_rule_add_metadata(ptr unsafe.Pointer, pkey *C.char, pvalue *C.char) {
	rule := (*Rule)(ptr)
	key := C.GoString(pkey)
	value := C.GoString(pvalue)
	rule.Metadata[key] = value
}

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
