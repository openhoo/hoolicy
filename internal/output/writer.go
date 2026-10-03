// Package output preserves the first output failure, including short writes,
// for commands and report renderers that emit multiple formatted fragments.
package output

import "io"

type Writer struct {
	Destination io.Writer
	err         error
}

func (w *Writer) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.Destination.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}

func (w *Writer) Err() error { return w.err }
