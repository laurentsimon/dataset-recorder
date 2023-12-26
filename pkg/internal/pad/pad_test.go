package pad

import (
	//"bytes"
	"bytes"
	"strconv"
	"testing"

	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/laurentsimon/dataset-recorder/pkg/internal/crypto/vrf"
	"github.com/laurentsimon/dataset-recorder/pkg/internal/merkletree"
)

var vrfKey vrf.PrivateKey

func init() {
	var err error
	vrfKey, err = vrf.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
}

// TODO: test tree insertions.

type testErrorRandReader struct{}

func (er testErrorRandReader) Read([]byte) (int, error) {
	return 0, errors.New("not enough entropy")
}

func mockRandReadWithErroringReader() (orig io.Reader) {
	orig = rand.Reader
	rand.Reader = testErrorRandReader{}
	return
}

func unMockRandReader(orig io.Reader) {
	rand.Reader = orig
}

func TestNewPADErrorWhileCreatingTree(t *testing.T) {
	origRand := mockRandReadWithErroringReader()
	defer unMockRandReader(origRand)

	pad, err := NewEmpty(vrfKey)
	if err == nil || pad != nil {
		t.Fatal("NewPad should return an error in case the tree creation failed")
	}
}

func BenchmarkCreateLargePAD(b *testing.B) {
	keyPrefix := "key"
	valuePrefix := []byte("value")

	// total number of entries in tree:
	NumEntries := uint64(1000000)

	b.ResetTimer()
	// benchmark creating a large tree (don't Update tree)
	for n := 0; n < b.N; n++ {
		_, err := createPad(NumEntries, keyPrefix, valuePrefix)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmarks which can be used produce data similar to Figure 7. in Section 5.
func BenchmarkPADUpdate100K(b *testing.B) { benchPADUpdate(b, 100000) }
func BenchmarkPADUpdate500K(b *testing.B) { benchPADUpdate(b, 500000) }

// make sure you have enough memory/cpu power if you want to run the benchmarks
// below; also give the benchmarks enough time to finish using the -timeout flag
func BenchmarkPADUpdate1M(b *testing.B)   { benchPADUpdate(b, 1000000) }
func BenchmarkPADUpdate2_5M(b *testing.B) { benchPADUpdate(b, 2500000) }
func BenchmarkPADUpdate5M(b *testing.B)   { benchPADUpdate(b, 5000000) }
func BenchmarkPADUpdate7_5M(b *testing.B) { benchPADUpdate(b, 7500000) }
func BenchmarkPADUpdate10M(b *testing.B)  { benchPADUpdate(b, 10000000) }

func benchPADUpdate(b *testing.B, entries uint64) {
	keyPrefix := "key"
	valuePrefix := []byte("value")
	// This takes a lot of time for a large number of entries:
	pad, err := createPad(uint64(entries), keyPrefix, valuePrefix)
	if err != nil {
		b.Fatal(err)
	}

	// Insert 1000 additional entries (as described in section 5.3):
	var i uint64
	for i = 0; i < 1000; i++ {
		key := keyPrefix + fmt.Sprint(i+entries)
		value := append(valuePrefix, byte(i+entries))
		if err := pad.Insert([]byte(key), value); err != nil {
			b.Fatal(err)
		}
	}
	// clone current PAD's state:
	orgTree := pad.tree.Clone()
	b.ResetTimer()

	// now benchmark re-hashing the tree:
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		pad.tree = orgTree.Clone()
		b.StartTimer()
		_ = pad.Hash()
	}
}

//
// END Benchmarks for Figure 7. in Section 5
//

func BenchmarkPADGetFrom10K(b *testing.B)  { benchPADGet(b, 10000) }
func BenchmarkPADGetFrom50K(b *testing.B)  { benchPADGet(b, 50000) }
func BenchmarkPADGetFrom100K(b *testing.B) { benchPADGet(b, 100000) }
func BenchmarkPADGetFrom500K(b *testing.B) { benchPADGet(b, 500000) }
func BenchmarkPADGetFrom1M(b *testing.B)   { benchPADGet(b, 1000000) }
func BenchmarkPADGetFrom5M(b *testing.B)   { benchPADGet(b, 5000000) }
func BenchmarkPADGetFrom10M(b *testing.B)  { benchPADGet(b, 10000000) }

func benchPADGet(b *testing.B, entries uint64) {
	keyPrefix := "key"
	valuePrefix := []byte("value")
	pad, err := createPad(entries, keyPrefix, valuePrefix)
	if err != nil {
		b.Fatal(err)
	}
	// ignore the tree creation:
	b.ResetTimer()

	// measure Gets in large tree (with NumEntries leafs)
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		var key string
		if n < int(entries) {
			key = keyPrefix + fmt.Sprint(n)
		} else {
			key = keyPrefix + fmt.Sprint(n%int(entries))
		}
		b.StartTimer()
		_, err := pad.Get([]byte(key))
		if err != nil {
			b.Fatalf("Coudldn't lookup key=%s", key)
		}
	}
}

// creates a PAD containing a tree with N entries (+ potential emptyLeafNodes)
// each key value pair has the form (keyPrefix+string(i), valuePrefix+string(i))
// for i = 0,...,N
// The STR will get updated every epoch defined by every multiple of
// `updateEvery`. If `updateEvery > N` createPAD won't update the STR.
// `afterCreateCB` and `afterInsertCB` are 2 callbacks which would be called
// before creating the PAD and after every inserting, respectively.
func createPad(N uint64, keyPrefix string, valuePrefix []byte) (*PAD, error) {
	pad, err := NewEmpty(vrfKey)
	if err != nil {
		return nil, err
	}

	for i := uint64(0); i < N; i++ {
		key := keyPrefix + strconv.FormatUint(i, 10)
		value := append(valuePrefix, byte(i))
		if err := pad.Insert([]byte(key), value); err != nil {
			return nil, fmt.Errorf("Couldn't set key=%s and value=%s. Error: %v",
				key, value, err)
		}
	}
	return pad, nil
}

func TestNewFromReader(t *testing.T) {
	keyPrefix := "key"
	valuePrefix := []byte("value")
	entries := uint64(10)
	var i uint64
	// Create pad1.
	pad1, err := NewEmpty(vrfKey)
	if err != nil {
		t.Fatal(err)
	}
	// Insert entries.
	for i = 0; i < entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		if err := pad1.Insert([]byte(key), value); err != nil {
			t.Fatal(err)
		}
	}
	// Inclusion proofs.
	for i = 0; i < entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		ap, err := pad1.Get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		if ap.pathProof.ProofType() != merkletree.ProofOfInclusion {
			t.Errorf("not a proof of inclusion: %v", key)
		}
		if ap.pathProof.Leaf.Value == nil {
			t.Error("Cannot find key:", key)
			return
		}
		if !bytes.Equal(ap.pathProof.Leaf.Value, value) {
			t.Error(key, "value mismatch\n")
		}
	}
	// Exclusion proofs.
	for i = entries + 1; i < 2*entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		ap, err := pad1.Get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		if ap.pathProof.ProofType() != merkletree.ProofOfExclusion {
			t.Errorf("not a proof of inclusion: %v", key)
		}
		if ap.pathProof.Leaf.Value != nil {
			t.Error("Found key:", key)
			return
		}
	}
	// Save pad1.
	var b1 bytes.Buffer
	var cpyb1 bytes.Buffer
	if err := pad1.WriteInternal(&b1); err != nil {
		t.Fatal(err)
	}
	cpyb1.Write(b1.Bytes())
	// Create a new pad from b1.
	pad2, err := NewFromReader(&b1, vrfKey)
	if err != nil {
		t.Fatal(err)
	}
	// Save pad2.
	var b2 bytes.Buffer
	if err := pad2.WriteInternal(&b2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cpyb1.Bytes(), b2.Bytes()) {
		t.Errorf("pad mismatch %v / %v", cpyb1.Bytes(), b2.Bytes())
	}
	// Inclusion proofs.
	for i = 0; i < entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		value := append(valuePrefix, byte(i))
		ap, err := pad2.Get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		if ap.pathProof.ProofType() != merkletree.ProofOfInclusion {
			t.Errorf("not a proof of inclusion: %v", key)
		}
		if ap.pathProof.Leaf.Value == nil {
			t.Error("Cannot find key:", key)
			return
		}
		if !bytes.Equal(ap.pathProof.Leaf.Value, value) {
			t.Error(key, "value mismatch\n")
		}
	}
	// Exclusion proofs.
	for i = entries + 1; i < 2*entries; i++ {
		key := keyPrefix + fmt.Sprint(i)
		ap, err := pad2.Get([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		if ap.pathProof.ProofType() != merkletree.ProofOfExclusion {
			t.Errorf("not a proof of inclusion: %v", key)
		}
		if ap.pathProof.Leaf.Value != nil {
			t.Error("Found key:", key)
			return
		}
	}
}
