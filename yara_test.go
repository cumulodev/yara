package yara

import (
	"reflect"
	"testing"
)

func TestNewCompiler(t *testing.T) {
	c, err := NewCompiler()
	assertEq(t, nil, err)

	c.Destroy()
}

func TestCompilerAddFile(t *testing.T) {
	c, err := NewCompiler()
	assertEq(t, nil, err)

	err = c.AddFile("", "rules/dummy.yar")
	assertEq(t, nil, err)

	c.Destroy()
}

func TestScanMem(t *testing.T) {
	c, err := NewCompiler()
	assertEq(t, nil, err)

	err = c.AddFile("", "rules/recursion.yar")
	assertEq(t, nil, err)

	engine, err := c.Rules()
	assertEq(t, nil, err)

	c.Destroy()

	rules, err := engine.ScanMemory([]byte("rule and condition"))
	assertEq(t, []string{"First", "Second"}, rules)
	assertEq(t, nil, err)
}

func TestScanFile(t *testing.T) {
	c, err := NewCompiler()
	assertEq(t, nil, err)

	err = c.AddFile("", "rules/recursion.yar")
	assertEq(t, nil, err)

	engine, err := c.Rules()
	assertEq(t, nil, err)

	c.Destroy()

	rules, err := engine.ScanFile("rules/recursion.yar")
	assertEq(t, []string{"First", "Second"}, rules)
	assertEq(t, nil, err)
}

func TestLoadRule(t *testing.T) {
	engine, err := LoadRules("rules/precompiled")
	assertEq(t, nil, err)

	rules, err := engine.ScanFile("rules/recursion.yar")
	assertEq(t, []string{"First", "Second"}, rules)
	assertEq(t, nil, err)
}

func assertEq(t *testing.T, expected interface{}, actual interface{}) {
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("Assertion error.\n\tExpected: %v\n\tActual:   %v", expected, actual)
	}
}
