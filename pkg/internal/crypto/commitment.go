package crypto

import "bytes"

// Commit can be used to create a cryptographic commit to some value (use
// NewCommit() for this purpose.
type Commit struct {
	// Salt is a cryptographic salt which will be hashed in addition
	// to the value.
	Salt []byte
	// Value is the actual value to commit to.
	Value []byte
}

// NewCommit creates a new cryptographic commit to the passed byte slices
// stuff (which won't be mutated). It creates a random salt before
// committing to the values.
func NewCommit(stuff ...[]byte) (*Commit, error) {
	salt, err := MakeRand()
	if err != nil {
		return nil, err
	}
	return &Commit{
		Salt:  salt,
		Value: Digest(append([][]byte{salt}, stuff...)...),
	}, nil
}

// Verify verifies that the underlying commit c was a commit to the passed
// byte slices stuff (which won't be mutated).
func (c *Commit) Verify(stuff ...[]byte) bool {
	return bytes.Equal(c.Value, Digest(append([][]byte{c.Salt}, stuff...)...))
}
