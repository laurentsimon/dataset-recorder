package merkletree

import (
	"bytes"
	"fmt"
	"io"

	"github.com/laurentsimon/dataset-recorder/pkg/internal/crypto"
	"github.com/laurentsimon/dataset-recorder/pkg/internal/utils"
)

type node struct {
	parent merkleNode
	level  uint32
}

type interiorNode struct {
	node
	leftChild  merkleNode
	rightChild merkleNode
	leftHash   []byte
	rightHash  []byte
}

type userLeafNode struct {
	node
	value      []byte
	index      []byte
	commitment *crypto.Commit
}

type emptyNode struct {
	node
	index []byte
}

func newInteriorNode(parent merkleNode, level uint32, prefixBits []bool) *interiorNode {
	prefixLeft := append([]bool(nil), prefixBits...)
	prefixLeft = append(prefixLeft, false)
	prefixRight := append([]bool(nil), prefixBits...)
	prefixRight = append(prefixRight, true)
	leftBranch := &emptyNode{
		node: node{
			level: level + 1,
		},
		index: utils.ToBytes(prefixLeft),
	}

	rightBranch := &emptyNode{
		node: node{
			level: level + 1,
		},
		index: utils.ToBytes(prefixRight),
	}
	newNode := &interiorNode{
		node: node{
			parent: parent,
			level:  level,
		},
		leftChild:  leftBranch,
		rightChild: rightBranch,
		leftHash:   nil,
		rightHash:  nil,
	}
	leftBranch.parent = newNode
	rightBranch.parent = newNode

	return newNode
}

type merkleNode interface {
	isEmpty() bool
	hash(*MerkleTree) []byte
	clone(*interiorNode) merkleNode
}

var _ merkleNode = (*userLeafNode)(nil)
var _ merkleNode = (*interiorNode)(nil)
var _ merkleNode = (*emptyNode)(nil)

func (n *interiorNode) hash(m *MerkleTree) []byte {
	if n.leftHash == nil {
		n.leftHash = n.leftChild.hash(m)
	}
	if n.rightHash == nil {
		n.rightHash = n.rightChild.hash(m)
	}
	return crypto.Digest(n.leftHash, n.rightHash)
}

func (n *userLeafNode) hash(m *MerkleTree) []byte {
	return crypto.Digest(
		[]byte{LeafIdentifier},               // K_leaf
		[]byte(m.nonce),                      // K_n
		[]byte(n.index),                      // i
		[]byte(utils.UInt32ToBytes(n.level)), // l
		[]byte(n.commitment.Value),           // commit(key|| value)
	)
}

func (n *emptyNode) hash(m *MerkleTree) []byte {
	return crypto.Digest(
		[]byte{EmptyBranchIdentifier},        // K_empty
		[]byte(m.nonce),                      // K_n
		[]byte(n.index),                      // i
		[]byte(utils.UInt32ToBytes(n.level)), // l
	)
}

func (n *interiorNode) clone(parent *interiorNode) merkleNode {
	newNode := &interiorNode{
		node: node{
			parent: parent,
			level:  n.level,
		},
		leftHash:  append([]byte{}, n.leftHash...),
		rightHash: append([]byte{}, n.rightHash...),
	}
	// TODO: remove panic().
	if n.leftChild == nil ||
		n.rightChild == nil {
		panic(ErrInvalidTree)
	}
	newNode.leftChild = n.leftChild.clone(newNode)
	newNode.rightChild = n.rightChild.clone(newNode)
	return newNode
}

func (n *userLeafNode) clone(parent *interiorNode) merkleNode {
	return &userLeafNode{
		node: node{
			parent: parent,
			level:  n.level,
		},
		value:      append([]byte{}, n.value...), // make a copy of value
		index:      append([]byte{}, n.index...), // make a copy of index
		commitment: n.commitment,
	}
}

func (n *emptyNode) clone(parent *interiorNode) merkleNode {
	return &emptyNode{
		node: node{
			parent: parent,
			level:  n.level,
		},
		index: append([]byte{}, n.index...), // make a copy of index
	}
}

func (n *userLeafNode) isEmpty() bool {
	return false
}

func (n *interiorNode) isEmpty() bool {
	return false
}

func (n *emptyNode) isEmpty() bool {
	return true
}

func writeBytes(writer io.Writer, b []byte) error {
	n, err := writer.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("%w: expected %d, got %d", ErrInvalidWrite, len(b), n)
	}
	return nil
}

func writeHeader(writer io.Writer, header []byte) error {
	return writeBytes(writer, header)
}

func writeLevel(writer io.Writer, level uint32) error {
	return writeBytes(writer, utils.UInt32ToBytes(level))
}

func writeIndex(writer io.Writer, index []byte) error {
	val := append([]byte{}, utils.LongToBytes(int64(len(index)))...)
	val = append(val, index...)
	return writeBytes(writer, val)
}

func writeKey(writer io.Writer, key []byte) error {
	val := append([]byte{}, utils.LongToBytes(int64(len(key)))...)
	val = append(val, key...)
	return writeBytes(writer, val)
}

func writeValue(writer io.Writer, value []byte) error {
	val := append([]byte{}, utils.LongToBytes(int64(len(value)))...)
	val = append(val, value...)
	return writeBytes(writer, val)
}

func writeCommitment(writer io.Writer, c *crypto.Commit) error {
	// 32 bytes salt.
	if err := writeBytes(writer, c.Salt); err != nil {
		return err
	}
	// Value.
	val := append([]byte{}, utils.LongToBytes(int64(len(c.Value)))...)
	val = append(val, c.Value...)
	if err := writeBytes(writer, val); err != nil {
		return err
	}
	return nil
}

func writeEmptyNode(writer io.Writer, en *emptyNode) error {
	// Write the header.
	if err := writeHeader(writer, []byte("E")); err != nil {
		return err
	}
	// Write the level.
	if err := writeLevel(writer, en.level); err != nil {
		return err
	}
	// Write the index.
	if err := writeIndex(writer, en.index); err != nil {
		return err
	}
	return nil
}

func writeInteriorNode(writer io.Writer, in *interiorNode) error {
	// Write the header.
	if err := writeHeader(writer, []byte("I")); err != nil {
		return err
	}
	// Write the level.
	if err := writeLevel(writer, in.level); err != nil {
		return err
	}
	return nil
}

func writeLeafNode(writer io.Writer, ul *userLeafNode) error {
	// Write the header.
	if err := writeHeader(writer, []byte("L")); err != nil {
		return err
	}
	// Write the level.
	if err := writeLevel(writer, ul.level); err != nil {
		return err
	}
	// Write the index.
	if err := writeIndex(writer, ul.index); err != nil {
		return err
	}
	// Write the value.
	if err := writeValue(writer, ul.value); err != nil {
		return err
	}
	// Write the commitment.
	if err := writeCommitment(writer, ul.commitment); err != nil {
		return err
	}

	return nil
}

func nodeWrite(m *MerkleTree, n merkleNode, writer io.Writer) error {
	switch v := n.(type) {
	case *emptyNode:
		// Empty node.
		return writeEmptyNode(writer, v)
	case *interiorNode:
		// Interior node.
		if err := writeInteriorNode(writer, v); err != nil {
			return err
		}
		// Record the left node.
		if err := nodeWrite(m, v.leftChild, writer); err != nil {
			return err
		}
		// Record the right node.
		if err := nodeWrite(m, v.rightChild, writer); err != nil {
			return err
		}
	case *userLeafNode:
		// Leaf node.
		if err := writeLeafNode(writer, v); err != nil {
			return err
		}
	default:
		panic("unreachable")
	}

	return nil
}

func readBytes(reader io.Reader, b []byte) error {
	n, err := reader.Read(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		if n != len(b) {
			return fmt.Errorf("%w: expected %d, got %d", ErrInvalidRead, len(b), n)
		}
	}
	return nil
}

func readArbitraryLengthBytes(reader io.Reader) ([]byte, error) {
	lenBytes := make([]byte, 8)
	if err := readBytes(reader, lenBytes); err != nil {
		return nil, err
	}
	len := utils.BytesToLong(lenBytes)
	contentBytes := make([]byte, len)
	if err := readBytes(reader, contentBytes); err != nil {
		return nil, err
	}
	return contentBytes, nil
}

func readHeader(reader io.Reader) ([]byte, error) {
	header := make([]byte, 1)
	if err := readBytes(reader, header); err != nil {
		return nil, err
	}
	return header, nil
}

func readLevel(reader io.Reader) (uint32, error) {
	levelBytes := make([]byte, 4)
	if err := readBytes(reader, levelBytes); err != nil {
		return 0, err
	}
	return utils.BytesToUInt32(levelBytes), nil
}

func readIndex(reader io.Reader) ([]byte, error) {
	return readArbitraryLengthBytes(reader)
}

func readValue(reader io.Reader) ([]byte, error) {
	return readArbitraryLengthBytes(reader)
}

func readCommitment(reader io.Reader) (*crypto.Commit, error) {
	// 32 bytes salt.
	saltBytes := make([]byte, crypto.HashSizeByte)
	if err := readBytes(reader, saltBytes); err != nil {
		return nil, err
	}
	// Value.
	valueBytes, err := readArbitraryLengthBytes(reader)
	if err != nil {
		return nil, err
	}
	return &crypto.Commit{
		Salt:  saltBytes,
		Value: valueBytes,
	}, nil
}

func readInteriorNode(reader io.Reader) (*interiorNode, error) {
	in, err := newMerkleNode(nil, reader)
	if err != nil {
		return nil, err
	}
	vin, ok := in.(*interiorNode)
	if !ok {
		return nil, fmt.Errorf("%w: not an interior node", ErrInvalidRead)
	}
	return vin, nil
}

func newMerkleNode(parent merkleNode, reader io.Reader) (merkleNode, error) {
	// Read the header.
	header, err := readHeader(reader)
	if err != nil {
		return nil, err
	}
	switch {
	case bytes.Equal([]byte("L"), header):
		// Read the level.
		level, err := readLevel(reader)
		if err != nil {
			return nil, err
		}
		// Read the index.
		index, err := readIndex(reader)
		if err != nil {
			return nil, err
		}
		// Read the value.
		value, err := readValue(reader)
		if err != nil {
			return nil, err
		}
		// Read the commitment.
		commitment, err := readCommitment(reader)
		if err != nil {
			return nil, err
		}
		return &userLeafNode{
			node: node{
				parent: parent,
				level:  level,
			},
			value:      value,
			index:      index,
			commitment: commitment,
		}, nil
	case bytes.Equal([]byte("I"), header):
		// Interior node.
		// Read the level.
		level, err := readLevel(reader)
		if err != nil {
			return nil, err
		}
		in := &interiorNode{
			node: node{
				parent: parent,
				level:  level,
			},
		}
		// Set the left child.
		in.leftChild, err = newMerkleNode(in, reader)
		if err != nil {
			return nil, err
		}
		// Set the right child.
		in.rightChild, err = newMerkleNode(in, reader)
		if err != nil {
			return nil, err
		}
		return in, nil

	case bytes.Equal([]byte("E"), header):
		// Empty node.
		// Read the level.
		level, err := readLevel(reader)
		if err != nil {
			return nil, err
		}
		// Read the index.
		index, err := readIndex(reader)
		if err != nil {
			return nil, err
		}
		return &emptyNode{
			node: node{
				parent: parent,
				level:  level,
			},
			index: append([]byte{}, index...), // make a copy of index
		}, nil
	}
	panic("unreachable")
}
