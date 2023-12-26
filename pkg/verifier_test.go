package pkg

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/laurentsimon/dataset-recorder/pkg/internal/merkletree"
)

func Test_VerifyInclusion(t *testing.T) {
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

	// Now create the prover and verifier.
	// The prover is created from the non-serialized recorder.
	p, err := newProverFromRecorder(r)
	if err != nil {
		t.Fatalf("cannot create prover: %v", err)
	}
	pubVerifData, err := p.Public()
	if err != nil {
		t.Fatalf("cannot get verifier's public data: %v", err)
	}
	v, err := NewVerifier(pubVerifData)
	if err != nil {
		t.Fatalf("cannot create verifier: %v", err)
	}
	for i = 0; i < entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		proof, err := p.Get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		if err := v.VerifyInclusion(*proof, []byte(key), value); err != nil {
			t.Fatal(err)
		}
	}
}

func Test_VerifyExclusion(t *testing.T) {
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

	// Now create the prover and verifier
	p, err := newProverFromRecorder(r)
	if err != nil {
		t.Fatalf("cannot create prover: %v", err)
	}
	pubVerifData, err := p.Public()
	if err != nil {
		t.Fatalf("cannot get verifier's public data: %v", err)
	}
	v, err := NewVerifier(pubVerifData)
	if err != nil {
		t.Fatalf("cannot create verifier: %v", err)
	}
	for i = entries + 1; i < 2*entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		proof, err := p.Get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		if err := v.VerifyExclusion(*proof, []byte(key), value); err != nil {
			t.Fatal(err)
		}
	}
}
