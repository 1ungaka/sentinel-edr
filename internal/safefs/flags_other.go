//go:build !unix

package safefs

const (
	noFollow = 0
	nonBlock = 0
)

func isSymlinkRefusal(error) bool { return false }
