package tcpdumper

import "io"

type RWPipe struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p *RWPipe) Close() error {
	if p.w != nil {
		p.w.Close()
	}
	if p.r != nil {
		p.r.Close()
	}
	return nil
}

func (p *RWPipe) Write(data []byte) (n int, err error) {
	return p.w.Write(data)
}

func (p *RWPipe) Read(data []byte) (n int, err error) {
	return p.r.Read(data)
}

func NewRWPipe() *RWPipe {
	r, w := io.Pipe()
	return &RWPipe{
		r: r,
		w: w,
	}
}
