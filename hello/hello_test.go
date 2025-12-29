package hello

import "testing"

func TestGetMessage(t *testing.T) {
	expected := "Hello, World!"
	actual := GetMessage()
	if actual != expected {
		t.Errorf("GetMessage() = %s; expected %s", actual, expected)
	}
}

func BenchmarkGetMessage(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GetMessage()
	}
}
