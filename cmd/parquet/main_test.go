package main

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/laurentsimon/dataset-recorder/pkg"
)

func Test_todo(t *testing.T) {
	t.Parallel()
	r, err := pkg.NewEmptyRecorder(nil)
	if err != nil {
		t.Fatalf("cannot create recorder: %v", err)
	}
	keyPrefix := "key"
	valuePrefix := []byte("value")
	entries := uint64(10)
	var i uint64
	for i = 0; i < entries; i++ {
		// TODO: download the files, reset.
		// TODO: select key to use, which should be the hash
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		if err := r.Insert([]byte(key), value); err != nil {
			t.Fatal(err)
		}
	}
	// Now save. Disk or mem?
	var b1 bytes.Buffer
	if err := r.WriteInternal(&b1); err != nil {
		t.Fatal(err)
	}
}
