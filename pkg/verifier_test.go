package pkg

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/laurentsimon/dataset-recorder/pkg/internal/merkletree"
)

func Test_VerifyInExclusion(t *testing.T) {
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
	// Save the recorder.
	var b bytes.Buffer
	if err := r.WriteInternal(&b); err != nil {
		t.Fatal(err)
	}
	cpyb := copyBuffer(b)
	cpybb := copyBuffer(b)
	// 1. Now create the prover and verifier.
	// The prover is created from the non-serialized recorder.
	p1, err := newProverFromRecorder(r)
	if err != nil {
		t.Fatalf("cannot create prover: %v", err)
	}
	// Save the prover.
	var b1 bytes.Buffer
	if err := p1.WriteInternal(&b1); err != nil {
		t.Fatal(err)
	}
	cpyb1 := copyBuffer(b1)
	// Verify that p1 and r have the same saved representation.
	if diff := cmp.Diff(cpyb1.Bytes(), cpyb.Bytes()); diff != "" {
		t.Fatalf("unexpected err (-want +got): \n%s", diff)
	}
	pubVerifData, err := p1.Public()
	if err != nil {
		t.Fatalf("cannot get verifier's public data: %v", err)
	}
	v, err := NewVerifier(pubVerifData)
	if err != nil {
		t.Fatalf("cannot create verifier: %v", err)
	}
	// Proofs of inclusion.
	for i = 0; i < entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		proof, err := p1.Get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		if err := v.VerifyInclusion(*proof, []byte(key), value); err != nil {
			t.Fatal(err)
		}
	}
	// Proofs of exclusion.
	for i = entries + 1; i < 2*entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		proof, err := p1.Get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		if err := v.VerifyExclusion(*proof, []byte(key), value); err != nil {
			t.Fatal(err)
		}
	}
	// 2. Now create the prover and verifier.
	// The prover is created from the serialized recorder.
	p2, err := NewProverFromReader(&cpyb, r.Private())
	if err != nil {
		t.Fatalf("cannot create prover: %v", err)
	}
	// Save the prover.
	var b2 bytes.Buffer
	if err := p2.WriteInternal(&b2); err != nil {
		t.Fatal(err)
	}
	cpyb2 := copyBuffer(b2)
	cpyb22 := copyBuffer(b2)
	// Verify that p2 and r have the same saved representation.
	if diff := cmp.Diff(cpyb2.Bytes(), cpybb.Bytes()); diff != "" {
		t.Fatalf("unexpected err (-want +got): \n%s", diff)
	}
	pubVerifData, err = p2.Public()
	if err != nil {
		t.Fatalf("cannot get verifier's public data: %v", err)
	}
	v, err = NewVerifier(pubVerifData)
	if err != nil {
		t.Fatalf("cannot create verifier: %v", err)
	}
	// Proofs of inclusion.
	for i = 0; i < entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		proof, err := p2.Get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		if err := v.VerifyInclusion(*proof, []byte(key), value); err != nil {
			t.Fatal(err)
		}
	}
	// Proofs of exclusion.
	for i = entries + 1; i < 2*entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		proof, err := p2.Get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		if err := v.VerifyExclusion(*proof, []byte(key), value); err != nil {
			t.Fatal(err)
		}
	}
	// 3. Now create the prover and verifier.
	// The prover is created from the serialized prover p2.
	p3, err := NewProverFromReader(&cpyb2, p2.Private())
	if err != nil {
		t.Fatalf("cannot create prover: %v", err)
	}
	// Save the prover.
	var b3 bytes.Buffer
	if err := p3.WriteInternal(&b3); err != nil {
		t.Fatal(err)
	}
	// Verify that p2 and p3 have the same saved representation.
	if diff := cmp.Diff(cpyb22.Bytes(), b3.Bytes()); diff != "" {
		t.Fatalf("unexpected err (-want +got): \n%s", diff)
	}
	pubVerifData, err = p3.Public()
	if err != nil {
		t.Fatalf("cannot get verifier's public data: %v", err)
	}
	v, err = NewVerifier(pubVerifData)
	if err != nil {
		t.Fatalf("cannot create verifier: %v", err)
	}
	// Proofs of inclusion.
	for i = 0; i < entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		proof, err := p3.Get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		if err := v.VerifyInclusion(*proof, []byte(key), value); err != nil {
			t.Fatal(err)
		}
	}
	// Proofs of exclusion.
	for i = entries + 1; i < 2*entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		proof, err := p3.Get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		if err := v.VerifyExclusion(*proof, []byte(key), value); err != nil {
			t.Fatal(err)
		}
	}
}

func copyBuffer(b bytes.Buffer) bytes.Buffer {
	var cpy bytes.Buffer
	cpy.Write(b.Bytes())
	return cpy
}
