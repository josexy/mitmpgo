package buf

import (
	"io"
	"unicode/utf8"
	"unsafe"
)

const ReadSize = 512

var (
	_ io.ReadWriter   = (*Buffer)(nil)
	_ io.ReaderFrom   = (*Buffer)(nil)
	_ io.WriterTo     = (*Buffer)(nil)
	_ io.StringWriter = (*Buffer)(nil)
	_ io.ByteReader   = (*Buffer)(nil)
	_ io.ByteWriter   = (*Buffer)(nil)
)

type Buffer struct {
	data  []byte
	start int
	end   int
}

func NewSize(size int) *Buffer {
	if size == 0 {
		return &Buffer{}
	}
	return From(make([]byte, size))
}

func As(data []byte) *Buffer {
	return &Buffer{
		data: data,
		end:  len(data),
	}
}

func From(data []byte) *Buffer {
	return &Buffer{data: data}
}

func (b *Buffer) Byte(index int) byte {
	return b.data[b.start+index]
}

func (b *Buffer) SetByte(index int, value byte) {
	b.data[b.start+index] = value
}

func (b *Buffer) TryGrow(n int) {
	if n < 0 {
		panic("cannot be negative")
	}
	b.tryGrowSlice(n)
}

func (b *Buffer) Advance(n int) {
	b.start += n
}

func (b *Buffer) Truncate(n int) {
	b.end = b.start + n
}

func (b *Buffer) Write(data []byte) (n int, err error) {
	if len(data) == 0 {
		return
	}
	b.tryGrowSlice(len(data))
	n = copy(b.data[b.end:b.Cap()], data)
	b.end += n
	return
}

func (b *Buffer) WriteByte(d byte) error {
	b.tryGrowSlice(1)
	b.data[b.end] = d
	b.end++
	return nil
}

func (b *Buffer) ReadAtLeast(r io.Reader, min int) (int64, error) {
	if min <= 0 {
		n, err := b.ReadFrom(r)
		return n, err
	}
	if b.IsFull() {
		return 0, io.ErrShortBuffer
	}
	n, err := io.ReadAtLeast(r, b.FreeBytes(), min)
	b.end += n
	return int64(n), err
}

func (b *Buffer) ReadFull(r io.Reader, size int) (n int, err error) {
	// we don't grow the slice here
	if b.end+size > b.Cap() {
		return 0, io.ErrShortBuffer
	}
	n, err = io.ReadFull(r, b.data[b.end:b.end+size])
	b.end += n
	return
}

func (b *Buffer) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		if b.IsFull() {
			b.tryGrowSlice(ReadSize)
		}
		var readN int
		readN, err = r.Read(b.FreeBytes())
		b.end += readN
		n += int64(readN)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return
		}
	}
}

func (b *Buffer) tryGrowSlice(n int) {
	// calculate minCapacity
	minCapacity := b.end + n

	// if slice is empty, create a new one
	if len(b.data) == 0 {
		newCap := nextslicecap(n, 0)
		b.data = make([]byte, newCap)
		return
	}

	if minCapacity > len(b.data) {
		// use Golang slice's grow strategy
		newCap := nextslicecap(minCapacity, len(b.data))
		newData := make([]byte, newCap)
		// only copy valid data
		if b.Len() > 0 {
			copy(newData, b.data[b.start:b.end])
		}

		b.data = newData
		b.end = b.end - b.start
		b.start = 0
	}
}

// See: https://github.com/golang/go/blob/master/src/runtime/slice.go#L289
func nextslicecap(newLen, oldCap int) int {
	newcap := oldCap
	doublecap := newcap + newcap
	if newLen > doublecap {
		return newLen
	}

	const threshold = 256
	if oldCap < threshold {
		return doublecap
	}
	for {
		// Transition from growing 2x for small slices
		// to growing 1.25x for large slices. This formula
		// gives a smooth-ish transition between the two.
		newcap += (newcap + 3*threshold) >> 2

		// We need to check `newcap >= newLen` and whether `newcap` overflowed.
		// newLen is guaranteed to be larger than zero, hence
		// when newcap overflows then `uint(newcap) > uint(newLen)`.
		// This allows to check for both with the same comparison.
		if uint(newcap) >= uint(newLen) {
			break
		}
	}

	// Set newcap to the requested cap when
	// the newcap calculation overflowed.
	if newcap <= 0 {
		return newLen
	}
	return newcap
}

func (b *Buffer) WriteRune(r rune) (int, error) {
	if uint32(r) < utf8.RuneSelf {
		b.WriteByte(byte(r))
		return 1, nil
	}
	n := utf8.RuneLen(r)
	if n == -1 {
		panic("the rune is not a valid value to encode in UTF-8")
	}
	b.tryGrowSlice(n)
	utf8.EncodeRune(b.data[b.end:b.end+n], r)
	b.end += n
	return n, nil
}

func (b *Buffer) WriteString(s string) (n int, err error) {
	if len(s) == 0 {
		return
	}

	b.tryGrowSlice(len(s))
	n = copy(b.data[b.end:b.Cap()], s)
	b.end += n
	return
}

func (b *Buffer) ReadRune() (r rune, size int, err error) {
	if b.IsEmpty() {
		return 0, 0, io.EOF
	}

	nb := b.data[b.start]
	if nb < utf8.RuneSelf {
		b.start++
		return rune(nb), 1, nil
	}
	r, n := utf8.DecodeRune(b.data[b.start:])
	b.start += n
	return r, n, nil
}

func (b *Buffer) ReadByte() (byte, error) {
	if b.IsEmpty() {
		return 0, io.EOF
	}

	nb := b.data[b.start]
	b.start++
	return nb, nil
}

func (b *Buffer) ReadBytes(n int) ([]byte, error) {
	if b.end-b.start < n {
		return nil, io.EOF
	}

	nb := b.data[b.start : b.start+n]
	b.start += n
	return nb, nil
}

func (b *Buffer) Read(data []byte) (n int, err error) {
	if b.IsEmpty() {
		return 0, io.EOF
	}
	n = copy(data, b.data[b.start:b.end])
	b.start += n
	return
}

func (b *Buffer) WriteTo(w io.Writer) (n int64, err error) {
	if nBytes := b.Len(); nBytes > 0 {
		m, e := w.Write(b.Bytes())
		if m > nBytes {
			panic("buf.Buffer.WriteTo: invalid Write count")
		}
		b.start += m
		n = int64(m)
		if e != nil {
			return n, e
		}
		// all bytes should have been written, by definition of Write method in io.Writer
		if m != nBytes {
			return n, io.ErrShortWrite
		}
	}
	b.Reset()
	return n, nil
}

func (b *Buffer) Resize(start, size int) {
	b.start = start
	b.end = b.start + size
}

func (b *Buffer) Reset() {
	b.start = 0
	b.end = 0
}

func (b *Buffer) Start() int {
	return b.start
}

func (b *Buffer) Len() int {
	return b.end - b.start
}

func (b *Buffer) Cap() int {
	return len(b.data)
}

func (b *Buffer) Bytes() []byte {
	return b.data[b.start:b.end]
}

func (b *Buffer) RawBytes() []byte {
	return b.data[0:b.Cap()]
}

func (b *Buffer) Slice(start, end int) []byte {
	if start < 0 {
		start = 0
	}
	start = b.start + start
	if end > b.Len() {
		end = b.Len()
	}
	end = b.start + end
	return b.data[start:end]
}

func (b *Buffer) Index(start int) []byte {
	return b.data[b.start+start : b.start+start]
}

func (b *Buffer) Available() int {
	return b.Cap() - b.end
}

func (b *Buffer) FreeBytes() []byte {
	return b.data[b.end:b.Cap()]
}

func (b *Buffer) IsEmpty() bool {
	return b.end-b.start == 0
}

func (b *Buffer) IsFull() bool {
	return b.end == b.Cap()
}

func (b *Buffer) String() string {
	if b == nil {
		return "<nil>"
	}
	if b.Len() == 0 {
		return ""
	}
	return unsafe.String(&b.Bytes()[0], b.Len())
}

func (b *Buffer) Clone() *Buffer {
	n := NewSize(len(b.data))
	copy(n.data[b.start:b.end], b.data[b.start:b.end])
	n.start = b.start
	n.end = b.end
	return n
}
