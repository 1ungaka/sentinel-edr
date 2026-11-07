//go:build race

package peeler

// raceSlow widens the timing slack the wall-clock tests allow: the race
// detector makes every decode several times slower, and the walls are fixed.
const raceSlow = 4
