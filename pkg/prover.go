package pkg

import (
	"io"

	"github.com/laurentsimon/dataset-recorder/pkg/internal/crypto/vrf"
	"github.com/laurentsimon/dataset-recorder/pkg/internal/pad"
)

type Prover struct {
	p *pad.PAD
}

type Proof struct {
	proof pad.Proof
}

func NewProverFromReader(reader io.ReadCloser, vrfKey []byte) (*Prover, error) {
	p, err := pad.NewFromReader(reader, vrf.PrivateKey(vrfKey))
	if err != nil {
		return nil, err
	}
	return &Prover{
		p: p,
	}, nil
}

// Create a prover frm a recorder. Used to simplify tests.
// Not exposed publically.
func newProverFromRecorder(r *Recorder) (*Prover, error) {
	return &Prover{
		p: r.p.Clone(),
	}, nil
}

// Get get the proof.
func (p *Prover) Get(key []byte) (*Proof, error) {
	proof, err := p.p.Get(key)
	if err != nil {
		return nil, err
	}
	return &Proof{
		proof: *proof,
	}, nil
}

// WriteInternal stores internal state of the recorder.
func (p *Prover) WriteInternal(writer io.WriteCloser) error {
	return p.p.WriteInternal(writer)
}

// Private returns private keys.
func (p *Prover) private() []byte {
	return p.p.Private()
}

// Public returns public data for verification.
func (p *Prover) Public() ([]byte, error) {
	return p.p.Public()
}
