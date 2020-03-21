package cifs

import (
	"bufio"
	"fmt"
	"io"
	"os"
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

func (stats *ClientStats) parseHeader(line string) {
	if _, err := fmt.Sscanf(line, "CIFS Session: %d", &stats.Header.CIFSSession); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "Share (unique mount targets): %d", &stats.Header.Targets); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "SMB Request/Response Buffer: %d Pool size: %d", &stats.Header.SMBReq, &stats.Header.SMBBuf); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "SMB Small Req/Resp Buffer: %d Pool size: %d", &stats.Header.SMBSmallReq, &stats.Header.SMBSmallBuf); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "Operations (MIDs): %d", &stats.Header.Op); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "%d session %d share reconnects", &stats.Header.Session, &stats.Header.ShareReconnects); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "Total vfs operations: %d maximum at one time: %d", &stats.Header.MaxOp, &stats.Header.AtOnce); err == nil {
		return
	}
}

func ParseClientStats(r io.Reader) (*ClientStats, error) {
	stats := &ClientStats{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		stats.parseHeader(line)
	}
	return stats, nil
}
