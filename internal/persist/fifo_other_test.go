//go:build !unix

package persist

import "testing"

func testFIFO(t *testing.T) { t.Skip("no FIFOs on this platform") }
