package merkletree

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/laurentsimon/dataset-recorder/pkg/internal/crypto"
	"github.com/laurentsimon/dataset-recorder/pkg/internal/utils"
)

var (
	// ErrInvalidTree indicates a panic due to
	// a malformed operation on the tree.
	ErrInvalidTree = errors.New("[merkletree] Invalid tree")
	// ErrInvalidWrite a problem to serialize.
	ErrInvalidWrite = errors.New("[merkletree] Invalid write")
	// ErrInvalidRead a problem to deserialize.
	ErrInvalidRead = errors.New("[merkletree] Invalid read")
)

const (
	// EmptyBranchIdentifier is the domain separation prefix for
	// empty node hashes.
	EmptyBranchIdentifier = 'E'

	// LeafIdentifier is the domain separation prefix for user
	// leaf node hashes.
	LeafIdentifier = 'L'
)

// MerkleTree represents the Merkle prefix tree data structure,
// which includes the root node, its hash, and a random tree-specific
// nonce.
type MerkleTree struct {
	nonce []byte
	root  *interiorNode
	hash  []byte
	dirty bool
}

// NewEmpty returns an empty Merkle prefix tree
// with a secure random nonce. The tree root is an interior node
// and its children are two empty leaf nodes.
func NewEmpty() (*MerkleTree, error) {
	root := newInteriorNode(nil, 0, []bool{})
	nonce, err := crypto.MakeRand()
	if err != nil {
		return nil, err
	}
	m := &MerkleTree{
		nonce: nonce,
		root:  root,
	}
	return m, nil
}

// NewFromReader loads a tree from a reader.
func NewFromReader(reader io.Reader) (*MerkleTree, error) {
	m := new(MerkleTree)
	// Set tree as dirty because the hash is not computed.
	m.dirty = true
	// Read the nonce.
	m.nonce = make([]byte, crypto.HashSizeByte)
	n, err := reader.Read(m.nonce)
	if err != nil {
		return nil, err
	}
	if n != crypto.HashSizeByte {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidWrite, crypto.HashSizeByte, n)
	}
	// Read the hash.
	hash := make([]byte, crypto.HashSizeByte)
	n, err = reader.Read(hash)
	if err != nil {
		return nil, err
	}
	if n != crypto.HashSizeByte {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidWrite, crypto.HashSizeByte, n)
	}
	// Read the tree.
	m.root, err = readInteriorNode(reader)
	if err != nil {
		return nil, err
	}

	// Compute the hash and compare to the read value.
	computedHash := m.Hash()
	if !bytes.Equal(hash, computedHash) {
		return nil, fmt.Errorf("%w: computed hash and stored hash mismatch", ErrInvalidRead)
	}
	return m, nil
}

// WriteInternal saves the tree to a writer.
func (m *MerkleTree) WriteInternal(writer io.Writer) error {
	// https://medium.com/@lukuoyu/leetcode-297-serialize-and-deserialize-binary-tree-tree-hard-23e158914772
	// First, make sure the hash is update to date.
	m.computeHash()
	// Write the nonce.
	n, err := writer.Write(m.nonce)
	if err != nil {
		return err
	}
	if n != len(m.nonce) {
		return fmt.Errorf("%w: expected %d, got %d", ErrInvalidWrite, len(m.nonce), n)
	}
	// Write the hash.
	n, err = writer.Write(m.hash)
	if err != nil {
		return err
	}
	if n != len(m.hash) {
		return fmt.Errorf("%w: expected %d, got %d", ErrInvalidWrite, len(m.hash), n)
	}
	return nodeWrite(m, m.root, writer)
}

func (m *MerkleTree) computeHash() {
	// Only recompute the hash if it's dirty.
	if !m.dirty {
		return
	}
	m.hash = m.root.hash(m)
	m.dirty = false
}

// Hash returns the hash of the root of the tree.
func (m *MerkleTree) Hash() []byte {
	m.computeHash()
	// Make a copy.
	h := make([]byte, len(m.hash))
	copy(h, m.hash)
	return h
}

// Get returns an AuthenticationPath used as a proof
// of inclusion/absence for the requested lookupIndex.
func (m *MerkleTree) Get(lookupIndex []byte) (*AuthenticationPath, error) {
	// Make sure the hashes are update to date.
	m.computeHash()

	lookupIndexBits := utils.ToBits(lookupIndex)
	depth := 0
	var nodePointer merkleNode
	nodePointer = m.root

	authPath := &AuthenticationPath{
		TreeNonce:   m.nonce,
		LookupIndex: lookupIndex,
	}

	for {
		if _, ok := nodePointer.(*userLeafNode); ok {
			// reached to a leaf node
			break
		}
		if _, ok := nodePointer.(*emptyNode); ok {
			// reached to an empty branch
			break
		}
		direction := lookupIndexBits[depth]
		var hashArr [crypto.HashSizeByte]byte
		if direction {
			copy(hashArr[:], nodePointer.(*interiorNode).leftHash)
			nodePointer = nodePointer.(*interiorNode).rightChild
		} else {
			copy(hashArr[:], nodePointer.(*interiorNode).rightHash)
			nodePointer = nodePointer.(*interiorNode).leftChild
		}
		authPath.PrunedTree = append(authPath.PrunedTree, hashArr)
		depth++
	}

	if nodePointer == nil {
		return nil, ErrInvalidTree
	}
	switch nodePointer.(type) {
	case *userLeafNode:
		pNode := nodePointer.(*userLeafNode)
		authPath.Leaf = &ProofNode{
			Level:   pNode.level,
			Index:   pNode.index,
			Value:   pNode.value,
			IsEmpty: false,
			Commitment: &crypto.Commit{
				Salt:  pNode.commitment.Salt,
				Value: pNode.commitment.Value,
			},
		}
		if bytes.Equal(nodePointer.(*userLeafNode).index, lookupIndex) {
			return authPath, nil
		}
		// reached a different leaf with a matching prefix
		// return a auth path including the leaf node without salt & value
		authPath.Leaf.Value = nil
		authPath.Leaf.Commitment.Salt = nil
		return authPath, nil
	case *emptyNode:
		pNode := nodePointer.(*emptyNode)
		authPath.Leaf = &ProofNode{
			Level:      pNode.level,
			Index:      pNode.index,
			Value:      nil,
			IsEmpty:    true,
			Commitment: nil,
		}
		return authPath, nil
	}
	return nil, ErrInvalidTree
}

// Set inserts or updates the value of the given index
// calculated from the key to the tree. It will generate a new commitment
// for the leaf node. In the case of an update, the leaf node's value and
// commitment are replaced with the new value and newly generated
// commitment.
func (m *MerkleTree) Set(index []byte, key, value []byte) error {
	commitment, err := crypto.NewCommit([]byte(key), value)
	if err != nil {
		return err
	}
	toAdd := userLeafNode{
		value:      append([]byte{}, value...), // make a copy of value
		index:      index,
		commitment: commitment,
	}
	m.insertNode(index, &toAdd)
	return nil
}

func (m *MerkleTree) insertNode(index []byte, toAdd *userLeafNode) {
	m.dirty = true
	indexBits := utils.ToBits(index)
	var depth uint32 // = 0
	var nodePointer merkleNode
	nodePointer = m.root

insertLoop:
	for {
		switch nodePointer.(type) {
		case *userLeafNode:
			// reached a "bottom" of the tree.
			// add a new interior node and push the previous leaf down
			// then continue insertion
			currentNodeUL := nodePointer.(*userLeafNode)
			if currentNodeUL.parent == nil {
				panic(ErrInvalidTree)
			}

			if bytes.Equal(currentNodeUL.index, toAdd.index) {
				// replace the value
				toAdd.parent = currentNodeUL.parent
				toAdd.level = currentNodeUL.level
				*currentNodeUL = *toAdd
				return
			}

			newInteriorNode := newInteriorNode(currentNodeUL.parent, depth, indexBits[:depth])

			direction := utils.GetNthBit(currentNodeUL.index, depth)
			if direction {
				newInteriorNode.rightChild = currentNodeUL
			} else {
				newInteriorNode.leftChild = currentNodeUL
			}
			currentNodeUL.level = depth + 1
			currentNodeUL.parent = newInteriorNode
			if newInteriorNode.parent.(*interiorNode).leftChild == nodePointer {
				newInteriorNode.parent.(*interiorNode).leftChild = newInteriorNode
			} else {
				newInteriorNode.parent.(*interiorNode).rightChild = newInteriorNode
			}
			nodePointer = newInteriorNode
		case *interiorNode:
			currentNodeI := nodePointer.(*interiorNode)
			direction := indexBits[depth]
			if direction { // go right
				currentNodeI.rightHash = nil
				if currentNodeI.rightChild.isEmpty() {
					currentNodeI.rightChild = toAdd
					toAdd.level = depth + 1
					toAdd.parent = currentNodeI
					break insertLoop
				} else {
					nodePointer = currentNodeI.rightChild
				}
			} else { // go left
				currentNodeI.leftHash = nil
				if currentNodeI.leftChild.isEmpty() {
					currentNodeI.leftChild = toAdd
					toAdd.level = depth + 1
					toAdd.parent = currentNodeI
					break insertLoop
				} else {
					nodePointer = currentNodeI.leftChild
				}
			}
			depth += 1
		default:
			panic(ErrInvalidTree)
		}
	}
}

// visits all leaf-nodes and calls callBack on each of them
// doesn't modify the underlying tree m
func (m *MerkleTree) visitLeafNodes(callBack func(*userLeafNode)) {
	visitULNsInternal(m.root, callBack)
}

func visitULNsInternal(nodePtr merkleNode, callBack func(*userLeafNode)) {
	switch nodePtr.(type) {
	case *userLeafNode:
		callBack(nodePtr.(*userLeafNode))
	case *interiorNode:
		if leftChild := nodePtr.(*interiorNode).leftChild; leftChild != nil {
			visitULNsInternal(leftChild, callBack)
		}
		if rightChild := nodePtr.(*interiorNode).rightChild; rightChild != nil {
			visitULNsInternal(rightChild, callBack)
		}
	case *emptyNode:
		// do nothing
	default:
		panic(ErrInvalidTree)
	}
}

// Clone returns a copy of the tree m.
// Any later change to the original tree m does not affect the cloned tree,
// and vice versa.
func (m *MerkleTree) Clone() *MerkleTree {
	return &MerkleTree{
		nonce: append([]byte{}, m.nonce...), // Make a copy of the nonce.
		root:  m.root.clone(nil).(*interiorNode),
		hash:  append([]byte{}, m.hash...), // Make a copy of the nonce.
	}
}
