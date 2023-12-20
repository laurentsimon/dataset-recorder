package pad

import (
	"errors"
	"fmt"
	"io"

	"github.com/laurentsimon/dataset-recorder/pkg/internal/crypto"
	"github.com/laurentsimon/dataset-recorder/pkg/internal/crypto/vrf"
	"github.com/laurentsimon/dataset-recorder/pkg/internal/merkletree"
)

var (
	// ErrSTRNotFound indicates that the STR has been evicted from
	// memory, because the maximum number of cached PAD snapshots
	// has been exceeded.
	ErrSTRNotFound = errors.New("[merkletree] STR not found")
)

// A PAD represents a persistent authenticated dictionary,
// and includes the underlying MerkleTree and VRF key.
type PAD struct {
	vrfKey vrf.PrivateKey
	tree   *merkletree.MerkleTree
}

type Proof struct {
	pathProof merkletree.AuthenticationPath
	vrfProof  []byte
}

type Public []byte

// NewEmpty creates an empty PAD.
func NewEmpty(vrfKey vrf.PrivateKey) (*PAD, error) {
	var err error
	pad := new(PAD)
	pad.vrfKey = vrfKey
	pad.tree, err = merkletree.NewEmpty()
	if err != nil {
		return nil, err
	}
	return pad, nil
}

// Load a pad from a reader and vrf private key.
func NewFromReader(reader io.ReadCloser, vrfKey vrf.PrivateKey) (*PAD, error) {
	return nil, nil
}

// WriteInternal saves a pad to a writer.
func (pad *PAD) WriteInternal(writer io.WriteCloser) error {
	// NOTE: We do not save the key.
	return pad.tree.WriteInternal(writer)
}

func (pad *PAD) Private() []byte {
	return pad.vrfKey
}

func (pad *PAD) Hash() []byte {
	return pad.tree.Hash()
}

func (pad *PAD) Public() ([]byte, error) {
	pubKey, err := pad.vrfKey.Public()
	if err != nil {
		return nil, err
	}

	return append([]byte(pad.Hash()), []byte(pubKey)...), nil
}

func (b Public) VerificationKey() []byte {
	return append([]byte{}, b[crypto.HashSizeByte:]...)
}

func (b Public) TreeHash() []byte {
	return append([]byte{}, b[:crypto.HashSizeByte]...)
}

func (p *Proof) PathProof() merkletree.AuthenticationPath {
	return p.pathProof
}

// Index uses the VRF private key of the PAD to compute
// the private index for the requested key.
func (pad *PAD) Index(key []byte) []byte {
	index, _ := pad.computePrivateIndex(key, pad.vrfKey)
	return index
}

// Insert computes the private index for the given key using
// the current VRF private key to create a new index-to-value binding,
// and inserts it into the PAD's underlying Merkle tree. This ensures
// the index-to-value binding will be included in the next PAD snapshot.
func (pad *PAD) Insert(key, value []byte) error {
	fmt.Printf("Adding value: %v, %v\n", string(key), string(value))
	return pad.tree.Set(pad.Index(key), []byte(key), value)
}

// Get searches the requested key from the tree,
// and returns the corresponding proof proving inclusion
// or absence of the requested key.
func (pad *PAD) Get(key []byte) (*Proof, error) {
	lookupIndex, vrfProof := pad.computePrivateIndex(key, pad.vrfKey)
	ap, err := pad.tree.Get(lookupIndex)
	if err != nil {
		return nil, err
	}
	return &Proof{
		pathProof: *ap,
		vrfProof:  vrfProof,
	}, nil
}

func (pad *PAD) computePrivateIndex(key []byte, vrfKey vrf.PrivateKey) (index, proof []byte) {
	index, proof = vrfKey.Prove(key)
	return
}

func (pad *PAD) Clone() *PAD {
	return &PAD{
		vrfKey: vrf.PrivateKey(append([]byte{}, []byte(pad.vrfKey)...)), // Make a copy of the key.
		tree:   pad.tree.Clone(),
	}
}
