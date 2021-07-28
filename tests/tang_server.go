package tests

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"testing"
)

type TangServer struct {
	binaryPath string
	keysDir    string
	listener   net.Listener
	quit       chan interface{}
	port       int
}

func NewTangServer(keysDir string) (*TangServer, error) {
	path, err := findTangdLocation()
	if err != nil {
		return nil, err
	}

	var l net.Listener
	l, err = net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}

	s := &TangServer{
		binaryPath: path,
		keysDir:    keysDir,
		listener:   l,
		port:       l.Addr().(*net.TCPAddr).Port,
		quit:       make(chan interface{}),
	}
	go s.serve()
	return s, nil
}

func (s *TangServer) Stop() {
	close(s.quit)
	_ = s.listener.Close()
}

func (s *TangServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				log.Println("accept error", err)
			}
		} else {
			s.handleConnection(conn)
			if err := conn.Close(); err != nil {
				log.Print(err)
			}
		}
	}
}

func (s *TangServer) handleConnection(conn net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			log.Println("read error", err)
			return
		}
		if n == 0 {
			return
		}

		tangCmd := exec.Command(s.binaryPath, s.keysDir)
		tangCmd.Stdin = bytes.NewReader(buf[:n])
		if testing.Verbose() {
			tangCmd.Stderr = os.Stderr
		}
		tangCmd.Stdout = conn
		if err := tangCmd.Run(); err != nil {
			log.Println(err)
		}
	}
}

func findTangdLocation() (string, error) {
	// different OS use different tang server binary location
	tangLocations := []string{
		"/usr/lib/",
		"/usr/lib/x86_64-linux-gnu/",
	}

	for _, l := range tangLocations {
		path := l + "tangd"
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("Cannot find 'tangd' binary location")
}
