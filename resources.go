package main

import "github.com/cau-edr/cau/internal/resources"

// Resource discovery is implemented in internal/resources so the `cau-mcp`
// server resolves resources identically. These aliases keep the CLI's call
// sites unchanged.
const (
	envSignatures = resources.EnvSignatures
	envRules      = resources.EnvRules
	envFuzzy      = resources.EnvFuzzy

	relSignatures = resources.RelSignatures
	relRules      = resources.RelRules
	relFuzzy      = resources.RelFuzzy
)

// findResource resolves a resource. explicit is the flag value ("" when the
// flag was not given). It returns the chosen path and, when nothing was found,
// the list of locations that were tried.
func findResource(explicit, env, rel string) (path string, searched []string) {
	return resources.Find(explicit, env, rel)
}
