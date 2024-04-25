package buffer

import (
	"errors"
	"fmt"
	"io"
)

// From https://stackoverflow.com/questions/20602131/io-writeseeker-and-io-readseeker-from-byte-or-file.

// Implements io.ReadWriteSeeker for testing purposes.
type Buffer struct {
	buffer []byte
	offset int64
}

// Creates new buffer that implements io.ReadWriteSeeker for testing purposes.
func New(reader io.Reader) (*Buffer, error) {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return &Buffer{
		buffer: bytes,
		offset: 0,
	}, nil
}

func (fb *Buffer) Bytes() []byte {
	return fb.buffer
}

func (fb *Buffer) Len() int {
	return len(fb.buffer)
}

func (fb *Buffer) Read(b []byte) (int, error) {
	available := len(fb.buffer) - int(fb.offset)
	if available == 0 {
		return 0, io.EOF
	}
	size := len(b)
	if size > available {
		size = available
	}
	copy(b, fb.buffer[fb.offset:fb.offset+int64(size)])
	fb.offset += int64(size)
	return size, nil
}

func (fb *Buffer) ReadAt(p []byte, off int64) (int, error) {
	_, err := fb.Seek(off, io.SeekStart)
	if err != nil {
		return -1, err
	}
	return fb.Read(p)
}

func (fb *Buffer) Write(b []byte) (int, error) {
	copied := copy(fb.buffer[fb.offset:], b)
	if copied < len(b) {
		fb.buffer = append(fb.buffer, b[copied:]...)
	}
	fb.offset += int64(len(b))
	return len(b), nil
}

func (fb *Buffer) Seek(offset int64, whence int) (int64, error) {
	var newOffset int64
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = fb.offset + offset
	case io.SeekEnd:
		newOffset = int64(len(fb.buffer)) + offset
	default:
		return 0, errors.New("Unknown Seek Method")
	}
	if newOffset > int64(len(fb.buffer)) || newOffset < 0 {
		return 0, fmt.Errorf("Invalid Offset %d", offset)
	}
	fb.offset = newOffset
	return newOffset, nil
}
