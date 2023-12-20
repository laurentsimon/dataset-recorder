package pkg

import (
	"errors"

	"github.com/laurentsimon/dataset-recorder/pkg/internal/crypto/vrf"
	"github.com/laurentsimon/dataset-recorder/pkg/internal/merkletree"
	"github.com/laurentsimon/dataset-recorder/pkg/internal/pad"
)

var (
	// ErrProofType indicates proof is of the wrong type.
	ErrProofType = errors.New("[verifier] mismatch proof type")
)

type Verifier struct {
	vrfPubKey vrf.PublicKey
	treeHash  []byte
}

func NewVerifier(public []byte) (*Verifier, error) {
	p := pad.Public(public)
	return &Verifier{
		vrfPubKey: p.VerificationKey(),
		treeHash:  p.TreeHash(),
	}, nil
}

// VerifyInclusion verifies the presence of the key.
func (r *Verifier) VerifyInclusion(proof Proof, key, value []byte) error {
	pp := proof.proof.PathProof()
	if (&pp).ProofType() != merkletree.ProofOfInclusion {
		return ErrProofType
	}
	return pp.Verify(key, value, r.treeHash)
}

// VerifyExclusion verifies the absence of the key.
func (r *Verifier) VerifyExclusion(proof Proof, key, value []byte) error {
	// TODO: get pad to expose Verify and path proof functions.
	pp := proof.proof.PathProof()
	if (&pp).ProofType() != merkletree.ProofOfExclusion {
		return ErrProofType
	}
	return pp.Verify(key, value, r.treeHash)
}
