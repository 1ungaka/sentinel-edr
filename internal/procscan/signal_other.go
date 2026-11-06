//go:build !unix

package procscan

import "errors"

func signalProcess(int, Action) error {
	return errors.New("process response is not supported on this platform")
}
