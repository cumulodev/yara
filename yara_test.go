package yara

import (
	"os"
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

	matches := []string{}
	err = engine.ScanMemory([]byte("rule and condition"), func(rule *Rule) {
		matches = append(matches, rule.Identifier)
	})
	assertEq(t, []string{"First", "Second"}, matches)
	assertEq(t, nil, err)
}

func TestScanReader(t *testing.T) {
	engine, err := LoadFromFile("rules/precompiled")
	assertEq(t, nil, err)

	file, err := os.Open("rules/recursion.yar")
	assertEq(t, nil, err)

	matches := []string{}
	err = engine.Scan(file, func(rule *Rule) {
		matches = append(matches, rule.Identifier)
	})

	file.Close()

	assertEq(t, []string{"First", "Second"}, matches)
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

	matches := []string{}
	err = engine.ScanFile("rules/recursion.yar", func(rule *Rule) {
		matches = append(matches, rule.Identifier)
	})
	assertEq(t, []string{"First", "Second"}, matches)
	assertEq(t, nil, err)
}

func TestLoadRule(t *testing.T) {
	_, err := LoadFromFile("rules/precompiled")
	assertEq(t, nil, err)
}

func TestSaveRule(t *testing.T) {
	engine, err := LoadFromFile("rules/precompiled")
	assertEq(t, nil, err)

	err = engine.Save("rules/precompiled")
	assertEq(t, nil, err)
}

func assertEq(t *testing.T, expected interface{}, actual interface{}) {
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("Assertion error.\n\tExpected: %v\n\tActual:   %v", expected, actual)
	}
}
