package safefs

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// ReadOperatorFile reads a small file the operator named on the command line,
// such as a key. It differs from ReadFile in accepting a pipe, because
// --sign-key <(pass show cau/key) is how a key stays off the disk, and that
// arrives here as /dev/fd/63.
//
// A pipe is still bounded, by limit in size and by wait in time: a process that
// never writes would otherwise hold a scheduled job forever. Partial data is
// never returned, since half a key is not a key. A FIFO with no writer reads as
// empty, which is an error here and not an empty result, so a passphrase cannot
// quietly become the empty string. Devices, sockets and directories are
// ErrNotRegular, and so is a pipe on a platform that cannot put a deadline on
// one, which refuses rather than risks the wait.
func ReadOperatorFile(path string, limit int64, wait time.Duration) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|nonBlock, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	switch {
	case fi.Mode().IsRegular():
		return ReadAll(f, fi, limit)
	case fi.Mode()&os.ModeNamedPipe == 0:
		return nil, fmt.Errorf("%s: %w (%s)", path, ErrNotRegular, fi.Mode().Type())
	}
	if err := f.SetReadDeadline(time.Now().Add(wait)); err != nil {
		return nil, fmt.Errorf("%s: %w (a pipe, and this platform cannot bound the wait for one)", path, ErrNotRegular)
	}
	data, err := ReadAll(f, fi, limit)
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return nil, fmt.Errorf("%s: the pipe did not finish within %s", path, wait)
	case err != nil:
		return nil, err
	case len(data) == 0:
		return nil, fmt.Errorf("%s: the pipe has no writer", path)
	}
	return data, nil
}
