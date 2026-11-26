//go:build !windows

package main

import (
	"os"
	"syscall"
)

type DiskUsageInfo struct {
	TotalBytes uint64 `json:"totalBytes"`
	FreeBytes  uint64 `json:"freeBytes"`
}

func queryDiskUsage(dir string) *DiskUsageInfo {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return nil
	}
	bsize := uint64(st.Bsize)
	total := st.Blocks * bsize
	avail := st.Bavail * bsize
	if total == 0 {
		return nil
	}
	return &DiskUsageInfo{
		TotalBytes: total,
		FreeBytes:  avail,
	}
}

func detectGoRuntimeName() string {
	if v := os.Getenv("SYNCNOW_RUNTIME"); v != "" {
		return v
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	return "linux-vps"
}
