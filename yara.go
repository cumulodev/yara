package yara

/*
#include <stdio.h>
#include <yara.h>
#include "cgoyara.h"
*/
import "C"

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"unsafe"
)

func init() {
	code := C.yr_initialize()
	if code != C.ERROR_SUCCESS {
		log.Fatalf("failed to initialize libyara!")
	}
}

func Finalize() error {
	code := C.yr_finalize()
	if code != C.ERROR_SUCCESS {
		return newError(code)
	}

	return nil
}

func newError(code C.int) error {
	return fmt.Errorf("libyara: %d", code)
}

type Compiler struct {
	handle *C.YR_COMPILER
}

func NewCompiler() (*Compiler, error) {
	var handle *C.YR_COMPILER
	code := C.yr_compiler_create(&handle)
	if code != C.ERROR_SUCCESS {
		return nil, newError(code)
	}

	return &Compiler{handle}, nil
}

func (c *Compiler) Destroy() {
	C.yr_compiler_destroy(c.handle)
}

func (c *Compiler) AddFile(ns, path string) error {
	cpath := C.CString(path)
	cmode := C.CString("r")
	cns := C.CString(ns)

	defer C.free(unsafe.Pointer(cpath))
	defer C.free(unsafe.Pointer(cmode))
	defer C.free(unsafe.Pointer(cns))

	fd := C.fopen(cpath, cmode)
	if fd == nil {
		return fmt.Errorf("libyara: failed to open %q", path)
	}

	defer C.fclose(fd)

	errors := C.yr_compiler_add_file(c.handle, fd, nil, cpath)
	if errors > 0 {
		return fmt.Errorf("libyara: failed to compile %q", path)
	}

	return nil
}

func (c *Compiler) AddString(ns, rule string) error {
	crule := C.CString(rule)
	cns := C.CString(ns)

	defer C.free(unsafe.Pointer(crule))
	defer C.free(unsafe.Pointer(cns))

	errors := C.yr_compiler_add_string(c.handle, crule, cns)
	if errors > 0 {
		return fmt.Errorf("libyara: failed to compile rule")
	}

	return nil
}

func (c *Compiler) Rules() (*Rules, error) {
	var handle *C.YR_RULES
	code := C.yr_compiler_get_rules(c.handle, &handle)
	if code != C.ERROR_SUCCESS {
		return nil, newError(code)
	}

	return &Rules{handle}, nil
}

type Rules struct {
	handle *C.YR_RULES
}

func LoadFromFile(path string) (*Rules, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer fh.Close()
	return LoadFromReader(fh)
}

func LoadFromReader(r io.Reader) (*Rules, error) {
	var handle *C.YR_RULES
	code := C.yr_rules_load_stream(readStream(r), &handle)
	if code != C.ERROR_SUCCESS {
		return nil, newError(code)
	}

	return &Rules{handle}, nil
}

func (r *Rules) Save(path string) error {
	fh, err := os.Create(path)
	if err != nil {
		return err
	}

	err = r.Write(fh)
	fh.Close()

	return err
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

func (r *Rules) ScanMemory(buffer []byte, fn Callback) error {
	data := (*C.uint8_t)(unsafe.Pointer(&buffer[0]))
	size := C.size_t(len(buffer))
	code := C.yr_rules_scan_mem(r.handle, data, size, 0, callback, unsafe.Pointer(&fn), 0)
	if code != C.ERROR_SUCCESS {
		return newError(code)
	}

	return nil
}

func (r *Rules) ScanFile(path string, fn Callback) error {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	code := C.yr_rules_scan_file(r.handle, cpath, 0, callback, unsafe.Pointer(&fn), 0)
	if code != C.ERROR_SUCCESS {
		return newError(code)
	}

	return nil
}

type Rule struct {
	Identifier string
	Tags       []string
	Metadata   map[string]string
}

func NewRule() *Rule {
	return &Rule{
		Metadata: make(map[string]string),
	}
}

type Callback func(rule *Rule)

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
