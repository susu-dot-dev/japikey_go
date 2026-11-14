package main

import (
	"strings"
	"testing"
)

func TestReadLimited(t *testing.T) {
	t.Run("within limit", func(t *testing.T) {
		got, err := readLimited(strings.NewReader("hello"), 5)
		if err != nil || got != "hello" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("one byte over limit is rejected, not truncated", func(t *testing.T) {
		_, err := readLimited(strings.NewReader("hello!"), 5)
		if err == nil {
			t.Fatal("expected error for oversized input")
		}
	})

	t.Run("endless input terminates", func(t *testing.T) {
		_, err := readLimited(endlessReader{}, maxInputSize)
		if err == nil {
			t.Fatal("expected error for endless input")
		}
	})

	t.Run("multi-line input is preserved", func(t *testing.T) {
		got, err := readLimited(strings.NewReader("a\nb\n"), 16)
		if err != nil || got != "a\nb\n" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
}

type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}
