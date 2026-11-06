package attack

import (
	"sort"
	"testing"
)

func TestCatalogConsistent(t *testing.T) {
	for id, tq := range catalog {
		if id != tq.ID {
			t.Errorf("key %q holds id %q", id, tq.ID)
		}
		if !ValidID(id) {
			t.Errorf("%q is not a valid technique id", id)
		}
		if tq.Name == "" || len(tq.Tactics) == 0 {
			t.Errorf("%q lacks a name or tactics", id)
		}
		if p := Parent(id); p != id {
			if _, ok := catalog[p]; !ok {
				t.Errorf("sub-technique %q has no parent %q in the catalog", id, p)
			}
		}
	}
	if Name("T1003") != "OS Credential Dumping" || Name("T9999") != "" {
		t.Error("Name lookup broken")
	}
	if !ValidID("T1027.002") || ValidID("T102") || ValidID("1027") || ValidID("T1027.02") {
		t.Error("ValidID shape check broken")
	}
	if ids := IDs(); len(ids) != len(catalog) || !sort.StringsAreSorted(ids) {
		t.Errorf("IDs() = %v", ids)
	}
}
