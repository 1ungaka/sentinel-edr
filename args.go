package main

import (
	"flag"
	"strings"
)

// interspersed moves flags ahead of positional arguments so fs.Parse sees them.
// The flag package stops at the first positional, so `cau scan /bin --no-yara`
// scanned a file called --no-yara and left YARA on. A -- still ends the flags,
// and what follows it stays positional, which is how to name a file that starts
// with a dash.
func interspersed(fs *flag.FlagSet, args []string) []string {
	var flags, rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			rest = append(rest, args[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' { // a lone - means stdin
			rest = append(rest, a)
			continue
		}
		flags = append(flags, a)
		if strings.Contains(a, "=") || !takesValue(fs, strings.TrimLeft(a, "-")) {
			continue
		}
		if i+1 == len(args) {
			return flags // Parse reports the missing value
		}
		i++
		flags = append(flags, args[i])
	}
	return append(append(flags, "--"), rest...)
}

// takesValue reports whether a flag consumes the next argument. An unknown flag
// does not, and Parse rejects it.
func takesValue(fs *flag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	if f == nil {
		return false
	}
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return !ok || !b.IsBoolFlag()
}
