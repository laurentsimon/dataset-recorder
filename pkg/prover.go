package pkg

import (
	"io"

	"github.com/laurentsimon/dataset-recorder/pkg/internal/pad"
)

// Prover exxtends a recorder with prooving capabilities.
type Prover struct {
	Recorder
}

type Proof struct {
	proof pad.Proof
}

func NewProverFromReader(reader io.Reader, private []byte) (*Prover, error) {
	r, err := NewRecorderFromReader(reader, private)
	if err != nil {
		return nil, err
	}
	return newProverFromRecorder(r)
}

// Create a prover from a recorder. Not exposed publicly.
func newProverFromRecorder(r *Recorder) (*Prover, error) {
	return &Prover{
		Recorder: *r,
	}, nil
}

// Get get the proof.
func (p *Prover) Get(key []byte) (*Proof, error) {
	proof, err := p.Recorder.p.Get(key)
	if err != nil {
		return nil, err
	}
	return &Proof{
		proof: *proof,
	}, nil
}
