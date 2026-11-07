//go:build !race

package peeler

// raceSlow is 1 outside the race detector: see race_test.go.
const raceSlow = 1
