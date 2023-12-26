package pkg

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/laurentsimon/dataset-recorder/pkg/internal/crypto/vrf"
	"github.com/laurentsimon/dataset-recorder/pkg/internal/pad"
)

type Recorder struct {
	p *pad.PAD
}

const version = 0x01

var (
	ErrInvalidVersion = errors.New("invalid version")
)

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

func NewRecorderFromReader(reader io.Reader, private []byte) (*Recorder, error) {
	if err := validateVersion(reader); err != nil {
		return nil, err
	}
	p, err := pad.NewFromReader(reader, vrf.PrivateKey(private))
	if err != nil {
		return nil, err
	}
	return &Recorder{
		p: p,
	}, nil
}

func validateVersion(reader io.Reader) error {
	versionBytes := make([]byte, 1)
	n, err := reader.Read(versionBytes)
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("wrote %d bytes, expected %d", n, 1)
	}
	if !bytes.Equal([]byte{version}, versionBytes) {
		return fmt.Errorf("%w: version not supported (%v)", ErrInvalidVersion, versionBytes)
	}
	return nil
}

// Insert inserts data.
func (r *Recorder) Insert(key, value []byte) error {
	return r.p.Insert(key, value)
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
func (r *Recorder) WriteInternal(writer io.Writer) error {
	n, err := writer.Write([]byte{version})
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("wrote %d bytes, expected %d", n, 1)
	}
	return r.p.WriteInternal(writer)
}

// Private returns private keys.
func (r *Recorder) Private() []byte {
	return r.p.Private()
}

// Public returns public data for verification.
func (r *Recorder) Public() ([]byte, error) {
	return r.p.Public()
}
