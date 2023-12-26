package pkg

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/laurentsimon/dataset-recorder/pkg/internal/merkletree"
)

func Test_newProverFromRecorder(t *testing.T) {
	t.Parallel()
	// First, let's create a recorder
	// and insert keys.
	r, err := NewEmptyRecorder(nil)
	if err != nil {
		t.Fatalf("cannot create recorder: %v", err)
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
	// Now create the prover.
	v, err := newProverFromRecorder(r)
	if err != nil {
		t.Fatalf("cannot crate prover: %v", err)
	}
	for i = 0; i < entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		proof, err := v.Get([]byte(key))
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

	for i = entries + 1; i < 2*entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		proof, err := v.Get([]byte(key))
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

func Test_NewProverFromReader(t *testing.T) {
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

	// Save recorder r1.
	var b1 bytes.Buffer
	var cpyb1 bytes.Buffer
	if err := r1.WriteInternal(&b1); err != nil {
		t.Fatal(err)
	}
	cpyb1.Write(b1.Bytes())
	// Create a prover p1 from b1.
	p2, err := NewProverFromReader(&b1, r1.Private())
	if err != nil {
		t.Fatal(err)
	}
	// Inclusion proofs.
	for i = 0; i < entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		proof, err := p2.Get([]byte(key))
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
		proof, err := p2.Get([]byte(key))
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
	// Save p2.
	var b2 bytes.Buffer
	var cpyb2 bytes.Buffer
	if err := p2.WriteInternal(&b2); err != nil {
		t.Fatal(err)
	}
	cpyb2.Write(b2.Bytes())
	// Verify that p2 and r1 have the same saved representation.
	if diff := cmp.Diff(cpyb1.Bytes(), b2.Bytes()); diff != "" {
		t.Fatalf("unexpected err (-want +got): \n%s", diff)
	}

	// Create p3 prover from p2.
	p3, err := NewProverFromReader(&b2, p2.Private())
	if err != nil {
		t.Fatal(err)
	}
	// Inclusion proofs.
	for i = 0; i < entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		proof, err := p3.Get([]byte(key))
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
		proof, err := p3.Get([]byte(key))
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
	// Save p3.
	var b3 bytes.Buffer
	var cpyb3 bytes.Buffer
	if err := p3.WriteInternal(&b3); err != nil {
		t.Fatal(err)
	}
	cpyb3.Write(b3.Bytes())
	// Verify that p3 and p2 have the same saved representation.
	if diff := cmp.Diff(cpyb2.Bytes(), cpyb3.Bytes()); diff != "" {
		t.Fatalf("unexpected err (-want +got): \n%s", diff)
	}
}
