package main

import "io"

type bufferedReaderAt struct {
	r      io.Reader
	buffer []byte
}

func NewBufferedReaderAt(r io.Reader) io.ReaderAt {
	return &bufferedReaderAt{r: r}
}

func (b *bufferedReaderAt) ReadAt(data []byte, off int64) (n int, err error) {
	endOff := off + int64(len(data))
	need := endOff - int64(len(b.buffer))
	if need > 0 {
		buf := make([]byte, need)
		var rn int
		rn, err = io.ReadFull(b.r, buf)
		b.buffer = append(b.buffer, buf[:rn]...)
	}
	if int64(len(b.buffer)) >= off {
		n = copy(data, b.buffer[off:])
	}
	if n == len(data) {
		err = nil
	}
	return
}
