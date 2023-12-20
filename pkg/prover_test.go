package pkg

import (
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
	// Finalize the recorder.
	r.Finalize()

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