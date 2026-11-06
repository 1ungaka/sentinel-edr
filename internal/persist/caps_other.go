//go:build !linux

package persist

func fileCaps(string) []byte { return nil }
