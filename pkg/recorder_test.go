package pkg

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/laurentsimon/dataset-recorder/pkg/internal/merkletree"
)

func Test_NewEmptyRecorder(t *testing.T) {
	t.Parallel()

	r, err := NewEmptyRecorder(nil)
	if err != nil {
		t.Fatalf("cannot created recorder: %v", err)
	}
	keyPrefix := "key"
	valuePrefix := []byte("value")
	entries := uint64(10)
	var i uint64
	for i = 0; i < entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		if err := r.Insert([]byte(key), value); err != nil {
			t.Fatal(err)
		}
		proof, err := r.get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		// Light proof verification.
		pp := proof.proof.PathProof()
		if (&pp).ProofType() != merkletree.ProofOfInclusion {
			t.Fatal(fmt.Errorf("not present: %v", key))
		}
		if diff := cmp.Diff(value, pp.Leaf.Value); diff != "" {
			t.Fatalf("unexpected err (-want +got): \n%s", diff)
		}
	}
	// Existent entries.
	for i = 0; i < entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		proof, err := r.get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		// Light proof verification.
		pp := proof.proof.PathProof()
		if (&pp).ProofType() != merkletree.ProofOfInclusion {
			t.Fatal(fmt.Errorf("not present: %v", key))
		}
		if diff := cmp.Diff(value, pp.Leaf.Value); diff != "" {
			t.Fatalf("unexpected err (-want +got): \n%s", diff)
		}
	}
	// Non-existent entries.
	for i = entries + 1; i < 2*entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		proof, err := r.get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		// Light proof verification.
		pp := proof.proof.PathProof()
		if (&pp).ProofType() != merkletree.ProofOfExclusion {
			t.Fatal(fmt.Errorf("not present: %v", key))
		}
		if diff := cmp.Diff([]byte(nil), pp.Leaf.Value); diff != "" {
			t.Fatalf("unexpected err (-want +got): \n%s", diff)
		}
	}
}

func Test_NewRecorderFromReader(t *testing.T) {
	t.Parallel()

	r1, err := NewEmptyRecorder(nil)
	if err != nil {
		t.Fatalf("cannot created recorder: %v", err)
	}
	keyPrefix := "key"
	valuePrefix := []byte("value")
	entries := uint64(10)
	var i uint64
	for i = 0; i < entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		if err := r1.Insert([]byte(key), value); err != nil {
			t.Fatal(err)
		}
	}
	// Inclusion proofs.
	for i = 0; i < entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		proof, err := r1.get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		// Light proof verification.
		pp := proof.proof.PathProof()
		if (&pp).ProofType() != merkletree.ProofOfInclusion {
			t.Fatal(fmt.Errorf("not present: %v", key))
		}
		if diff := cmp.Diff(value, pp.Leaf.Value); diff != "" {
			t.Fatalf("unexpected err (-want +got): \n%s", diff)
		}
	}
	// Exlusion proofs.
	for i = entries + 1; i < 2*entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		proof, err := r1.get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		// Light proof verification.
		pp := proof.proof.PathProof()
		if (&pp).ProofType() != merkletree.ProofOfExclusion {
			t.Fatal(fmt.Errorf("not present: %v", key))
		}
		if diff := cmp.Diff([]byte(nil), pp.Leaf.Value); diff != "" {
			t.Fatalf("unexpected err (-want +got): \n%s", diff)
		}
	}
	// Save r1.
	var b1 bytes.Buffer
	var cpyb1 bytes.Buffer
	if err := r1.WriteInternal(&b1); err != nil {
		t.Fatal(err)
	}
	cpyb1.Write(b1.Bytes())
	// Create a new recorder from b1.
	r2, err := NewRecorderFromReader(&b1, r1.Private())
	if err != nil {
		t.Fatal(err)
	}
	// Inclusion proofs.
	for i = 0; i < entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		proof, err := r2.get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		// Light proof verification.
		pp := proof.proof.PathProof()
		if (&pp).ProofType() != merkletree.ProofOfInclusion {
			t.Fatal(fmt.Errorf("not present: %v", key))
		}
		if diff := cmp.Diff(value, pp.Leaf.Value); diff != "" {
			t.Fatalf("unexpected err (-want +got): \n%s", diff)
		}
	}
	// Exlusion proofs.
	for i = entries + 1; i < 2*entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		proof, err := r2.get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		// Light proof verification.
		pp := proof.proof.PathProof()
		if (&pp).ProofType() != merkletree.ProofOfExclusion {
			t.Fatal(fmt.Errorf("not present: %v", key))
		}
		if diff := cmp.Diff([]byte(nil), pp.Leaf.Value); diff != "" {
			t.Fatalf("unexpected err (-want +got): \n%s", diff)
		}
	}
	// Save r2.
	var b2 bytes.Buffer
	if err := r2.WriteInternal(&b2); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(cpyb1.Bytes(), b2.Bytes()); diff != "" {
		t.Fatalf("unexpected err (-want +got): \n%s", diff)
	}
}
