package main

// utility class that helps to wrap a command line tool into a pipe-like structure

import (
	"io"
	"os/exec"
)

type pipeCommandReader struct {
	cmd  *exec.Cmd
	pipe io.ReadCloser
}

func (r pipeCommandReader) Read(p []byte) (n int, err error) {
	return r.pipe.Read(p)
}

func (r pipeCommandReader) Close() error {
	_ = r.pipe.Close()
	return r.cmd.Wait()
}

// newPipeCommandReader creates a new pipe command
// r becomes STDIN for the command
// the function returns a reader that contains information from the command STDOUT
func newPipeCommandReader(r io.Reader, app string, args ...string) (io.ReadCloser, error) {
	cmd := exec.Command(app, args...)
	cmd.Stdin = r
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return pipeCommandReader{cmd, pipe}, nil
}

type pipeCommandWriter struct {
	cmd  *exec.Cmd
	pipe io.WriteCloser
}

func (w pipeCommandWriter) Write(p []byte) (n int, err error) {
	return w.pipe.Write(p)
}

func (w pipeCommandWriter) Close() error {
	_ = w.pipe.Close()
	return w.cmd.Wait()
}

// newPipeCommandWriter creates a new pipe command
// w becomes STDOUT for the command
// the function returns a writer that becomes STDIN for the command
func newPipeCommandWriter(w io.Writer, app string, args ...string) (io.WriteCloser, error) {
	cmd := exec.Command(app, args...)
	cmd.Stdout = w
	pipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return pipeCommandWriter{cmd, pipe}, nil
}
