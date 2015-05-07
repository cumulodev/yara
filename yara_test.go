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

	name := ""
	err = engine.ScanMemory([]byte("rule and condition"), func(rule *Rule) CallbackStatus {
		name = rule.Identifier
		return Abort
	})

	assertEq(t, "First", name)
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

	name := ""
	err = engine.ScanFile("rules/recursion.yar", func(rule *Rule) CallbackStatus {
		name = rule.Identifier
		return Abort
	})

	assertEq(t, "First", name)
	assertEq(t, nil, err)
}

func TestScanContinue(t *testing.T) {
	c, err := NewCompiler()
	assertEq(t, nil, err)

	err = c.AddFile("", "rules/recursion.yar")
	assertEq(t, nil, err)

	engine, err := c.Rules()
	assertEq(t, nil, err)

	c.Destroy()

	name := ""
	err = engine.ScanFile("rules/recursion.yar", func(rule *Rule) CallbackStatus {
		name = rule.Identifier
		return Continue
	})

	assertEq(t, "Second", name)
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

func TestStackGrowth(t *testing.T) {
	c, err := NewCompiler()
	assertEq(t, nil, err)

	err = c.AddFile("", "rules/recursion.yar")
	assertEq(t, nil, err)

	engine, err := c.Rules()
	assertEq(t, nil, err)

	c.Destroy()

	n := 50
	ch := make(chan int)

	for i := 0; i < n; i++ {
		go func() {
			name := "foo"

			// use some stack memory to trigger split stack check
			var buf [4096]byte
			use(buf[:])

			err := engine.ScanFile("rules/recursion.yar", func(rule *Rule) CallbackStatus {
				name = rule.Identifier
				return Abort
			})

			assertEq(t, "First", name)
			assertEq(t, nil, err)
			ch <- 1
		}()
	}

	for i := 0; i < n; i++ {
		<-ch
	}
}

var Used byte

func use(buf []byte) {
	for _, c := range buf {
		Used += c
	}
}
