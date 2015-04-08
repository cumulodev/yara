package yara

/*
#include <stdio.h>
#include <yara.h>

int cgo_yr_callback(int msg, void* msg_data, void* user_data);
const char* cgo_rule_identifier(YR_RULE* rule);
*/
import "C"

import (
	"fmt"
	"log"
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

func LoadRules(path string) (*Rules, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	var handle *C.YR_RULES
	code := C.yr_rules_load(cpath, &handle)
	if code != C.ERROR_SUCCESS {
		return nil, newError(code)
	}

	return &Rules{handle}, nil
}

func (r *Rules) Save(path string) error {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	code := C.yr_rules_save(r.handle, cpath)
	if code != C.ERROR_SUCCESS {
		return newError(code)
	}

	return nil
}

func (r *Rules) ScanMemory(buffer []byte) ([]string, error) {
	data := &yrResult{
		matches: []string{},
	}
	code := C.yr_rules_scan_mem(r.handle, (*C.uint8_t)(unsafe.Pointer(&buffer[0])), C.size_t(len(buffer)), 0, (C.YR_CALLBACK_FUNC)(unsafe.Pointer(C.cgo_yr_callback)), unsafe.Pointer(data), 0)
	if code != C.ERROR_SUCCESS {
		return nil, newError(code)
	}

	return data.matches, nil
}

func (r *Rules) ScanFile(path string) ([]string, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	data := &yrResult{
		matches: []string{},
	}
	code := C.yr_rules_scan_file(r.handle, cpath, 0, (C.YR_CALLBACK_FUNC)(unsafe.Pointer(C.cgo_yr_callback)), unsafe.Pointer(data), 0)
	if code != C.ERROR_SUCCESS {
		return nil, newError(code)
	}

	return data.matches, nil
}

//export cgo_yr_callback
func cgo_yr_callback(msg C.int, msg_data unsafe.Pointer, user_data unsafe.Pointer) C.int {
	if msg != C.CALLBACK_MSG_RULE_MATCHING {
		return C.CALLBACK_CONTINUE
	}

	rule := (*C.YR_RULE)(msg_data)
	user := (*yrResult)(user_data)
	user.matches = append(user.matches, C.GoString(C.cgo_rule_identifier(rule)))
	return C.CALLBACK_CONTINUE
}

type yrResult struct {
	matches []string
}
