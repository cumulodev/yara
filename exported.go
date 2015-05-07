package yara

/*
#include <stdio.h>
#include <stdio.h>
#include <yara.h>
#include "cgo.h"
*/
import "C"

import (
	"io"
	"unsafe"
)

//export goStreamRead
func goStreamRead(ptr unsafe.Pointer, size C.size_t, count C.size_t, prw unsafe.Pointer) C.size_t {
	r := *(*io.Reader)(prw)

	buffer := make([]byte, int(size))
	n, err := io.ReadAtLeast(r, buffer, int(size))
	if err != nil {
		return 0
	}

	C.memcpy(ptr, (unsafe.Pointer)(&buffer[0]), C.size_t(n))
	return 1
}

//export goStreamWrite
func goStreamWrite(ptr unsafe.Pointer, size C.size_t, count C.size_t, prw unsafe.Pointer) C.size_t {
	w := *(*io.Writer)(prw)

	buffer := make([]byte, int(size))
	C.memcpy((unsafe.Pointer)(&buffer[0]), ptr, size)

	_, err := w.Write(buffer)
	if err != nil {
		return 0
	}

	return 1
}

//export goCallback
func goCallback(p unsafe.Pointer, data *C.YR_RULE) C.int {
	rule := NewRule()
	C.translate_rule(unsafe.Pointer(rule), data)

	f := (*(*Callback)(unsafe.Pointer(&p)))
	return C.int(f(rule))
}

//export goRuleSetIdentifier
func goRuleSetIdentifier(ptr unsafe.Pointer, identifier *C.char) {
	rule := (*Rule)(ptr)
	rule.Identifier = C.GoString(identifier)
}

//export goRuleAddTag
func goRuleAddTag(ptr unsafe.Pointer, tag *C.char) {
	rule := (*Rule)(ptr)
	rule.Tags = append(rule.Tags, C.GoString(tag))
}

//export goMetadataAddString
func goMetadataAddString(ptr unsafe.Pointer, pkey *C.char, pvalue *C.char) {
	rule := (*Rule)(ptr)
	key := C.GoString(pkey)
	value := C.GoString(pvalue)
	rule.Metadata[key] = value
}

//export goMetadataAddNumber
func goMetadataAddNumber(ptr unsafe.Pointer, pkey *C.char, value C.int) {
	rule := (*Rule)(ptr)
	key := C.GoString(pkey)
	rule.Metadata[key] = int(value)
}

//export goMetadataAddBool
func goMetadataAddBool(ptr unsafe.Pointer, pkey *C.char, value C.int) {
	rule := (*Rule)(ptr)
	key := C.GoString(pkey)
	rule.Metadata[key] = (int(value) != 0)
}
