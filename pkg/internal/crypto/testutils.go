package crypto

import (
	"bytes"

	"github.com/laurentsimon/dataset-recorder/pkg/internal/crypto/vrf"
)

// NewStaticTestVRFKey returns a static VRF private key for _tests_.
func NewStaticTestVRFKey() vrf.PrivateKey {
	sk, err := vrf.GenerateKey(bytes.NewReader(
		[]byte("deterministic tests need 256 bit")))
	if err != nil {
		panic(err)
	}
	return sk
}
