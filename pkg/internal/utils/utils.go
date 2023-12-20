package utils

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// GetNthBit finds the bit in the byte array bs
// at offset, and determines whether it is 1 or 0.
// It returns true if the nth bit is 1, false otherwise.
func GetNthBit(bs []byte, offset uint32) bool {
	arrayOffset := offset / 8
	bitOfByte := offset % 8

	masked := int(bs[arrayOffset] & (1 << uint(7-bitOfByte)))
	return masked != 0
}

// LongToBytes converts an int64 variable to byte array
// in little endian format.
func LongToBytes(num int64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(num))
	return buf
}

// ULongToBytes converts an uint64 variable to byte array
// in little endian format.
func ULongToBytes(num uint64) []byte {
	return LongToBytes(int64(num))
}

// UInt32ToBytes converts an uint32 variable to byte array
// in little endian format.
func UInt32ToBytes(num uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, num)
	return buf
}

// WriteFile writes buf to a file whose path is indicated by filename.
func WriteFile(filename string, buf []byte, perm os.FileMode) error {
	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("Can't write file. File '%s' already exists\n",
			filename)
	}

	if err := ioutil.WriteFile(filename, buf, perm); err != nil {
		return err
	}
	return nil
}

// ToBytes converts a slice of bits into
// a slice of bytes.
// In each byte, the bits are ordered MSB to LSB.
func ToBytes(bits []bool) []byte {
	bs := make([]byte, (len(bits)+7)/8)
	for i := 0; i < len(bits); i++ {
		if bits[i] {
			bs[i/8] |= (1 << 7) >> uint(i%8)
		}
	}
	return bs
}

// ToBits converts a slice of bytes into
// a slice of bits.
// In each byte, the bits are ordered MSB to LSB.
func ToBits(bs []byte) []bool {
	bits := make([]bool, len(bs)*8)
	for i := 0; i < len(bits); i++ {
		bits[i] = (bs[i/8]<<uint(i%8))&(1<<7) > 0
	}
	return bits
}

// ReplaceFile writes buf to a file whose path is indicated by filename.
func ReplaceFile(filename string, buf []byte, perm os.FileMode) error {
	if err := ioutil.WriteFile(filename, buf, perm); err != nil {
		return err
	}
	return nil
}

// ResolvePath returns the absolute path of file.
// This will use other as a base path if file is just a file name.
func ResolvePath(file, other string) string {
	if !filepath.IsAbs(file) {
		file = filepath.Join(filepath.Dir(other), file)
	}
	return file
}
