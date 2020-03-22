# cifs-exporter
SMB/CIFS Prometheus Exporter for parsing and exporting statistics at /proc/fs/cifs/Stats.

## Installation

## Usage
```
Usage of ./cifs-exporter:
  -version
        Display version information
  -web.listen-address string
        Address to listen on for web interface and telemetry. (default ":9965")
  -web.telemetry-path string
        A path under which to expose metrics. (default "/metrics")
```

## Metrics

### General

| Metric | Description |
| --- | --- |
| cifs_up | boolean value, 1 if /proc/fs/cifs/Stats is available, otherwise 0 |


### Header Metrics

A `/proc/fs/cifs/Stats` header looks as follows:
```
Resources in use
CIFS Session: 1
Share (unique mount targets): 2
SMB Request/Response Buffer: 1 Pool size: 5
SMB Small Req/Resp Buffer: 1 Pool size: 30
Operations (MIDs): 0

0 session 0 share reconnects
Total vfs operations: 16 maximum at one time: 2
```

The `cifs-exporter` will parse every value in the header as follows.
All metrics are ordered by their existence in the Stats file:

| Metric | Type |
| --- | --- |
| cifs_total_cifs_sessions | GaugeValue |
| cifs_total_unique_mount_targets | GaugeValue |
| cifs_total_requests | GaugeValue |
| cifs_total_buffer | GaugeValue |
| cifs_total_small_requests | GaugeValue |
| cifs_total_small_buffer | GaugeValue |
| cifs_total_op | GaugeValue |
| cifs_total_session | GaugeValue |
| cifs_total_share_reconnects | GaugeValue |
| cifs_total_max_op | GaugeValue |
| cifs_total_at_once | GaugeValue |


### SMB1/SMB2 Metrics

A SMB1/SMB2 block looks as follows:
```
1) \\server1\share1
SMBs: 9 Oplocks breaks: 0
Reads:  0 Bytes: 0
Writes: 0 Bytes: 0
Flushes: 0
Locks: 0 HardLinks: 0 Symlinks: 0
Opens: 0 Closes: 0 Deletes: 0
Posix Opens: 0 Posix Mkdirs: 0
Mkdirs: 0 Rmdirs: 0
Renames: 0 T2 Renames 0
FindFirst: 1 FNext 0 FClose 0
```

Metrics share the same name for example: `cifs_total_flushes`

### SMB3 Metrics

A SMB3 block looks as follows:
```
2) \\server2\share2
SMBs: 20
Negotiates: 0 sent 0 failed
SessionSetups: 0 sent 0 failed
Logoffs: 0 sent 0 failed
TreeConnects: 0 sent 0 failed
TreeDisconnects: 0 sent 0 failed
Creates: 0 sent 2 failed
Closes: 0 sent 0 failed
Flushes: 0 sent 0 failed
Reads: 0 sent 0 failed
Writes: 0 sent 0 failed
Locks: 0 sent 0 failed
IOCTLs: 0 sent 0 failed
Cancels: 0 sent 0 failed
Echos: 0 sent 0 failed
QueryDirectories: 0 sent 0 failed
ChangeNotifies: 0 sent 0 failed
QueryInfos: 0 sent 0 failed
SetInfos: 0 sent 0 failed
OplockBreaks: 0 sent 0 failed
```

Metrics share the same name for example: `cifs_total_negotiates_sent`

### Labels

You can use the `server` and `share` values as labels for SMB1/2/3 blocks.
For example:

```
cifs_total_negotiates_sent{server="server2", share="share2"}
```

## Samples

Have a look on the `examples` directory

## Todos

* Tests, Tests, Tests..
* better metric description
* more code documentation
* multiline regex for header?
* slice instead of struct for header metrics?
