package cifs

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
)

type ClientStats struct {
	Header      Header
	SMB1List    []*SMB1
	SMB2List    []*SMB2
	CacheId     uint64
	CacheServer string
	CacheShare  string
}

type SMB1 struct {
	Server      string
	Share       string
	SMB         uint64
	OpLocks     uint64
	Reads       uint64
	ReadsBytes  uint64
	Writes      uint64
	WritesBytes uint64
	Flushes     uint64
	Locks       uint64
	Hardlinks   uint64
	Symlinks    uint64
	Opens       uint64
	Closes      uint64
	Deletes     uint64
	PosixOpens  uint64
	PosixMkdirs uint64
	Mkdirs      uint64
	Rmdirs      uint64
	Renames     uint64
	T2Renames   uint64
	FindFirst   uint64
	FNext       uint64
	FClose      uint64
}

type SMB2 struct {
	Server                 string
	Share                  string
	SMB                    uint64
	NegotiatesSent         uint64
	NegotiatesFailed       uint64
	SessionSetupsSent      uint64
	SessionSetupsFailed    uint64
	LogoffsSent            uint64
	LogoffsFailed          uint64
	TreeConnectsSent       uint64
	TreeConnectsFailed     uint64
	TreeDisconnectsSent    uint64
	TreedisconnectsFailed  uint64
	CreatesSent            uint64
	CreatesFailed          uint64
	ClosesSent             uint64
	ClosesFailed           uint64
	FlushesSent            uint64
	FlushesFailed          uint64
	ReadsSent              uint64
	ReadsFailed            uint64
	WritesSent             uint64
	WritesFailed           uint64
	LocksSent              uint64
	LocksFailed            uint64
	IOCTLsSent             uint64
	IOCTLsFailed           uint64
	CancelsSent            uint64
	CancelsFailed          uint64
	EchosSent              uint64
	EchosFailed            uint64
	QueryDirectoriesSent   uint64
	QueryDirectoriesFailed uint64
	ChangeNotifiesSent     uint64
	ChangeNotifiesFailed   uint64
	QueryInfosSent         uint64
	QueryInfosFailed       uint64
	SetInfosSent           uint64
	SetInfosFailed         uint64
	OpLockBreaksSent       uint64
	OpLockBreaksFailed     uint64
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

var re = regexp.MustCompile(`(?m)(?:(?:(?P<SMBID>\d+)\) \\\\(?P<Server>[A-Za-z1-9-.]+)(?P<Share>.+)\nSMBs:\s+(?P<SMB>\d+) Oplocks breaks:\s+(?P<OpLocks>\d+)\nReads:\s+(?P<Reads>\d+) Bytes:\s+(?P<ReadsBytes>\d+)\nWrites:\s+(?P<Writes>\d+) Bytes:\s+(?P<WritesBytes>\d+)\nFlushes:\s+(?P<Flushes>\d+)\nLocks:\s+(?P<Locks>\d+) HardLinks:\s+(?P<Hardlinks>\d+) Symlinks:\s+(?P<Symlinks>\d+)\nOpens:\s+(?P<Opens>\d+) Closes:\s+(?P<Closes>\d+) Deletes:\s+(?P<Deletes>\d+)\nPosix Opens:\s+(?P<PosixOpens>\d+) Posix Mkdirs:\s+(?P<PosixMkdirs>\d+)\nMkdirs:\s+(?P<Mkdirs>\d+) Rmdirs:\s+(?P<Rmdirs>\d+)\nRenames:\s+(?P<Renames>\d+) T2 Renames\s+(?P<T2Renames>\d+)\nFindFirst:\s+(?P<FindFirst>\d+) FNext\s+(?P<FNext>\d+) FClose\s+(?P<FClose>\d+)|(?P<SMB3ID>\d+)\) \\\\(?P<SMB3Server>[A-Za-z1-9-.]+)(?P<SMB3Share>.+)\nSMBs:\s+(?P<SMB3>\d+)\nNegotiates:\s+(?P<NegotiatesSent>\d+) sent\s+(?P<NegotiatesFailed>\d+) failed\nSessionSetups:\s+(?P<SessionSetupsSent>\d+) sent\s+(?P<SessionSetupsFailed>\d+) failed\nLogoffs:\s+(?P<LogoffsSent>\d+) sent\s+(?P<LogoffsFailed>\d+) failed\nTreeConnects:\s+(?P<TreeConnectsSent>\d+) sent\s+(?P<TreeConnectsFailed>\d+) failed\nTreeDisconnects:\s+(?P<TreeDisconnectsSent>\d+) sent\s+(?P<TreeDisconnectsFailed>\d+) failed\nCreates:\s+(?P<CreatesSent>\d+) sent\s+(?P<CreatesFailed>\d+) failed\nCloses:\s+(?P<ClosesSent>\d+) sent\s+(?P<ClosesFailed>\d+) failed\nFlushes:\s+(?P<FlushesSent>\d+) sent\s+(?P<FlushesFailed>\d+) failed\nReads:\s+(?P<ReadsSent>\d+) sent\s+(?P<ReadsFailed>\d+) failed\nWrites:\s+(?P<WritesSent>\d+) sent\s+(?P<WritesFailed>\d+) failed\nLocks:\s+(?P<LocksSent>\d+) sent\s+(?P<LocksFailed>\d+) failed\nIOCTLs:\s+(?P<IOCTLsSent>\d+) sent\s+(?P<IOCTLsFailed>\d+) failed\nCancels:\s+(?P<CancelsSent>\d+) sent\s+(?P<CancelsFailed>\d+) failed\nEchos:\s+(?P<EchosSent>\d+) sent\s+(?P<EchosFailed>\d+) failed\nQueryDirectories:\s+(?P<QueryDirectoriesSent>\d+) sent\s+(?P<QueryDirectoriesFailed>\d+) failed\nChangeNotifies:\s+(?P<ChangeNotifiesSent>\d+) sent\s+(?P<ChangeNotifiesFailed>\d+) failed\nQueryInfos:\s+(?P<QueryInfosSent>\d+) sent\s+(?P<QueryInfosFailed>\d+) failed\nSetInfos:\s+(?P<SetInfosSent>\d+) sent\s+(?P<SetInfosFailed>\d+) failed\nOplockBreaks:\s+(?P<OpLockBreaksSent>\d+) sent\s+(?P<OpLockBreaksFailed>\d+) failed)+)`)

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

func (stats *ClientStats) parseSMBBlocks(file string) ([][]string, []string) {
	matches := re.FindAllStringSubmatch(file, -1)
	expNames := re.SubexpNames()
	for i := 1; i < len(expNames); i++ {
		fmt.Println(expNames[i])
	}
	return matches, expNames
}

func ParseClientStats(r io.Reader) (*ClientStats, error) {
	stats := &ClientStats{}
	scanner := bufio.NewScanner(r)
	// parse Header
	headerLen := 9
	for scanner.Scan() {
		if headerLen == 0 {
			break
		}
		line := scanner.Text()
		stats.parseHeader(line)
		headerLen--
	}
	// construct SMB block file
	var file string
	for scanner.Scan() {
		line := scanner.Text()
		file += line + "\n"
	}
	stats.parseSMBBlocks(file)
	return stats, nil
}
