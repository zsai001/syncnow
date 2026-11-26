//go:build windows

package main

import "os"

type DiskUsageInfo struct {
	TotalBytes uint64 `json:"totalBytes"`
	FreeBytes  uint64 `json:"freeBytes"`
}

func queryDiskUsage(_ string) *DiskUsageInfo {
	return nil
}

func detectGoRuntimeName() string {
	if v := os.Getenv("SYNCNOW_RUNTIME"); v != "" {
		return v
	}
	return "go-self-hosted"
}
