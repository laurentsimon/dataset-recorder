package pkg

import (
	"errors"
	"io"

	"github.com/laurentsimon/dataset-recorder/pkg/internal/crypto/vrf"
	"github.com/laurentsimon/dataset-recorder/pkg/internal/pad"
)

var (
	// ErrFinalized indicates the tree is fanialized.
	ErrFinalized = errors.New("[recorder] Finalized recorder")
)

type Recorder struct {
	p     *pad.PAD
	final bool
}

func NewEmptyRecorder(rnd io.Reader) (*Recorder, error) {
	vrfKey, err := vrf.GenerateKey(rnd)
	if err != nil {
		return nil, err
	}
	p, err := pad.NewEmpty(vrfKey)
	if err != nil {
		return nil, err
	}
	return &Recorder{
		p: p,
	}, nil
}

func NewRecorderFromReader(reader io.ReadCloser, vrfKey []byte) (*Recorder, error) {
	p, err := pad.NewFromReader(reader, vrf.PrivateKey(vrfKey))
	if err != nil {
		return nil, err
	}
	return &Recorder{
		p: p,
	}, nil
}

// Insert inserts data.
func (r *Recorder) Insert(key, value []byte) error {
	if r.final {
		return ErrFinalized
	}
	return r.p.Insert(key, value)
}

// Finalize the pad.
func (r *Recorder) Finalize() {
	// Force computation of the hashes in the tree.
	_ = r.p.Hash()
	r.final = true
}

// get gets a proof for a key. Only used for testing
// so not exposed.
func (r *Recorder) get(key []byte) (*Proof, error) {
	proof, err := r.p.Get(key)
	if err != nil {
		return nil, err
	}
	return &Proof{
		proof: *proof,
	}, nil
}

// WriteInternal stores internal state of the recorder.
func (r *Recorder) WriteInternal(writer io.WriteCloser) error {
	return r.p.WriteInternal(writer)
}

// private returns private keys.
func (r *Recorder) private() []byte {
	return r.p.Private()
}

// Public returns public data for verification.
func (r *Recorder) Public() ([]byte, error) {
	return r.p.Public()
}
