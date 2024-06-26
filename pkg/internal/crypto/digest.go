package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/sha3"
)

const (
	// HashSizeByte is the size of the hash output in bytes.
	HashSizeByte = 32
	// HashID identifies the used hash as a string.
	HashID = "SHAKE128"
)

// Digest hashes all passed byte slices.
// The passed slices won't be mutated.
func Digest(ms ...[]byte) []byte {
	h := sha3.NewShake128()
	for _, m := range ms {
		h.Write(m)
	}
	ret := make([]byte, HashSizeByte)
	h.Read(ret)
	return ret
}

// MakeRand returns a random slice of bytes.
// It returns an error if there was a problem while generating
// the random slice.
// It is different from the 'standard' random byte generation as it
// hashes its output before returning it; by hashing the system's
// PRNG output before it is send over the wire, we aim to make the
// random output less predictable (even if the system's PRNG isn't
// as unpredictable as desired).
// See https://trac.torproject.org/projects/tor/ticket/17694
func MakeRand() ([]byte, error) {
	r := make([]byte, HashSizeByte)
	if _, err := rand.Read(r); err != nil {
		return nil, err
	}
	// Do not directly reveal bytes from rand.Read on the wire
	return Digest(r), nil
}
