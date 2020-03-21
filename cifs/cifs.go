package cifs

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

type ClientStats struct {
	Header Header
}

type Header struct {
	CIFSSession     uint64
	Targets         uint64
	SMBReq          uint64
	SMBBuf          uint64
	SMBSmallReq     uint64
	SMBSmallBuf     uint64
	Op              uint64
	Session         uint64
	ShareReconnects uint64
	MaxOp           uint64
	AtOnce          uint64
}

func NewClientStats() (*ClientStats, error) {
	f, err := os.Open("cifs/stats_example.txt")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseClientStats(f)
}

func (stats *ClientStats) parseHeader(line string) error {
	switch {
	case strings.Contains(line, "CIFS Session:"):
		if _, err := fmt.Sscanf(line, "CIFS Session: %d", &stats.Header.CIFSSession); err != nil {
			return err
		}
	case strings.Contains(line, "Share (unique mount targets):"):
		if _, err := fmt.Sscanf(line, "Share (unique mount targets): %d", &stats.Header.Targets); err != nil {
			return err
		}
	}
	return nil
}

func ParseClientStats(r io.Reader) (*ClientStats, error) {
	stats := &ClientStats{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if err := stats.parseHeader(line); err != nil {
			return nil, err
		}
	}
	return stats, nil
}
