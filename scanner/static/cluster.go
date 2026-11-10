package static

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash/fnv"
	"math"
	"sort"
	"strings"
)

// MinHashSize is the number of hash functions in an import MinHash signature.
// 64 gives a Jaccard estimate with a standard error of about 0.06.
const MinHashSize = 64

// MinHash is a locality-sensitive signature of a set of import names: two
// sets with Jaccard similarity J agree on each slot with probability J.
type MinHash [MinHashSize]uint64

// ImportMinHash computes the signature of an import-name set. Names are
// de-duplicated and lower-cased; an empty set yields the all-max signature,
// which is similar to nothing.
func ImportMinHash(imports []string) MinHash {
	var sig MinHash
	for i := range sig {
		sig[i] = math.MaxUint64
	}
	seen := make(map[string]bool, len(imports))
	var seed [8]byte
	for _, name := range imports {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		for i := 0; i < MinHashSize; i++ {
			h := fnv.New64a()
			binary.LittleEndian.PutUint64(seed[:], uint64(i)*0x9E3779B97F4A7C15+1)
			h.Write(seed[:])
			h.Write([]byte(name))
			if v := h.Sum64(); v < sig[i] {
				sig[i] = v
			}
		}
	}
	return sig
}

// Similarity estimates the Jaccard similarity of the two underlying sets.
func (a MinHash) Similarity(b MinHash) float64 {
	same := 0
	for i := range a {
		if a[i] == b[i] {
			same++
		}
	}
	return float64(same) / float64(MinHashSize)
}

// Empty reports whether the signature came from an empty set.
func (a MinHash) Empty() bool {
	for _, v := range a {
		if v != math.MaxUint64 {
			return false
		}
	}
	return true
}

// ClusterItem is one file offered to the Clusterer.
type ClusterItem struct {
	// ID identifies the file (path or SHA256).
	ID      string
	Imphash string
	Sig     MinHash
	// Imports is the size of the import set, for reporting.
	Imports int
}

// Cluster is a group of files with similar import tables.
type Cluster struct {
	// ID is derived from the sorted member IDs, so the same grouping always
	// gets the same ID and a different grouping never collides with it.
	ID      string   `json:"id"`
	Members []string `json:"members"`
	// Imphash is set when every member shares one exact import hash.
	Imphash string `json:"imphash,omitempty"`
	// MinSimilarity is the lowest pairwise similarity that joined the cluster.
	MinSimilarity float64 `json:"min_similarity"`
	// Kind is "imphash" for exact groups and "import-lsh" for near groups.
	Kind string `json:"kind"`
}

// Clusterer groups files by import-table similarity: exact imphash groups
// first, then banded LSH over MinHash signatures with a Jaccard floor.
type Clusterer struct {
	items []ClusterItem
	bands int
	rows  int
}

// NewClusterer returns a Clusterer with 16 bands of 4 rows, which makes pairs
// above ~0.6 similarity almost certain candidates and pairs below ~0.3 almost
// never.
func NewClusterer() *Clusterer { return &Clusterer{bands: 16, rows: 4} }

// Add registers a file.
func (c *Clusterer) Add(item ClusterItem) { c.items = append(c.items, item) }

// Len is the number of registered files.
func (c *Clusterer) Len() int { return len(c.items) }

// Clusters computes the groups. minSimilarity is the Jaccard floor for near
// groups (0 < minSimilarity <= 1; 0 selects 0.6). Singletons are omitted:
// a file that resembles nothing is not a cluster.
func (c *Clusterer) Clusters(minSimilarity float64) []Cluster {
	if minSimilarity <= 0 || minSimilarity > 1 {
		minSimilarity = 0.6
	}
	n := len(c.items)
	parent := make([]int, n)
	minSim := make([]float64, n)
	for i := range parent {
		parent[i] = i
		minSim[i] = 1
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	union := func(a, b int, sim float64) {
		ra, rb := find(a), find(b)
		if ra == rb {
			if sim < minSim[ra] {
				minSim[ra] = sim
			}
			return
		}
		if rb < ra {
			ra, rb = rb, ra
		}
		parent[rb] = ra
		m := minSim[ra]
		if minSim[rb] < m {
			m = minSim[rb]
		}
		if sim < m {
			m = sim
		}
		minSim[ra] = m
	}

	// Exact imphash groups.
	byImp := map[string][]int{}
	for i, it := range c.items {
		if it.Imphash != "" {
			byImp[it.Imphash] = append(byImp[it.Imphash], i)
		}
	}
	for _, idx := range byImp {
		for k := 1; k < len(idx); k++ {
			union(idx[0], idx[k], 1)
		}
	}

	// A file already united by a shared non-empty imphash carries the same
	// signature as its group, so its mutual LSH pairs would only repeat what
	// the exact pass settled. One representative per imphash group enters the
	// pair enumeration — without this, one large set of identical binaries
	// costs every pair inside every shared bucket. A file with no imphash
	// has no exact group and speaks for itself.
	lshSkip := make([]bool, n) // audit:ok bounded: n is the number of analysed items
	for _, idx := range byImp {
		for _, i := range idx[1:] {
			lshSkip[i] = true
		}
	}

	// LSH candidates.
	buckets := map[string][]int{}
	for i, it := range c.items {
		if it.Sig.Empty() {
			continue
		}
		for b := 0; b < c.bands; b++ {
			h := fnv.New64a()
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], uint64(b))
			h.Write(buf[:])
			for r := 0; r < c.rows; r++ {
				binary.LittleEndian.PutUint64(buf[:], it.Sig[b*c.rows+r])
				h.Write(buf[:])
			}
			key := string(buf[:0]) + hex.EncodeToString(h.Sum(nil))
			buckets[key] = append(buckets[key], i)
		}
	}
	checked := map[[2]int]bool{}
	for _, idx := range buckets {
		for a := 0; a < len(idx); a++ {
			ia := idx[a]
			if lshSkip[ia] {
				continue
			}
			for b := a + 1; b < len(idx); b++ {
				ib := idx[b]
				if lshSkip[ib] {
					continue
				}
				pair := [2]int{ia, ib}
				if checked[pair] {
					continue
				}
				checked[pair] = true
				if sim := c.items[ia].Sig.Similarity(c.items[ib].Sig); sim >= minSimilarity {
					union(ia, ib, sim)
				}
			}
		}
	}

	groups := map[int][]int{}
	for i := range c.items {
		r := find(i)
		groups[r] = append(groups[r], i)
	}
	var out []Cluster
	for root, members := range groups {
		if len(members) < 2 {
			continue
		}
		cl := Cluster{MinSimilarity: minSim[root], Kind: "import-lsh"}
		imp := c.items[members[0]].Imphash
		sameImp := imp != ""
		for _, m := range members {
			cl.Members = append(cl.Members, c.items[m].ID)
			if c.items[m].Imphash != imp {
				sameImp = false
			}
		}
		sort.Strings(cl.Members)
		if sameImp {
			cl.Imphash = imp
			cl.Kind = "imphash"
			cl.MinSimilarity = 1
		}
		sum := sha256.Sum256([]byte(strings.Join(cl.Members, "\x00")))
		cl.ID = hex.EncodeToString(sum[:6])
		out = append(out, cl)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Members) != len(out[j].Members) {
			return len(out[i].Members) > len(out[j].Members)
		}
		return out[i].ID < out[j].ID
	})
	return out
}
