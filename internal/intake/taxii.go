package intake

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// A TAXII 2.1 client for one thing: polling a collection for STIX objects.
//
// TAXII ("Trusted Automated eXchange of Intelligence Information", OASIS) is
// the transport most intel platforms expose STIX over, MISP and OpenCTI
// included. The client implements the one endpoint intake needs,
//
//	GET {collection}/objects/?added_after=<ts>&limit=<n>&next=<cursor>
//
// with the envelope pagination of the 2.1 specification ("more" / "next").
// Discovery, API-root listing, manifests and writes are out of scope: the
// operator names the collection, which is also the only host the engine will
// talk to. Like every other fetch in the engine it runs only from an explicit
// command, and everything about the response is bounded.
//
// Polling is incremental. The server stamps each page with
// X-TAXII-Date-Added-Last; a caller that persists that value (see TAXIIState)
// and passes it back as AddedAfter on the next run receives only what was
// added since, which is what makes a scheduled pull cheap.

const (
	// TAXIIMediaType is the media type a TAXII 2.1 server serves and accepts.
	TAXIIMediaType = "application/taxii+json;version=2.1"

	// DefaultTAXIIMaxPages bounds one poll. A server that keeps answering
	// "more" cannot hold the run open forever.
	DefaultTAXIIMaxPages = 200
	// DefaultTAXIIMaxObjects bounds the objects one poll accumulates.
	DefaultTAXIIMaxObjects = 500000

	taxiiHeaderLast = "X-TAXII-Date-Added-Last"
)

// TAXIIOptions configures one poll of a collection.
type TAXIIOptions struct {
	// CollectionURL is the collection resource, e.g.
	// https://intel.example/api/v21/collections/<id>/ . The objects endpoint
	// is resolved under it.
	CollectionURL string
	// AddedAfter, when set, asks only for objects added after this RFC 3339
	// timestamp (the previous poll's LastAdded).
	AddedAfter string
	// Authorization, when set, is sent as the Authorization header. The
	// caller sources it from an environment variable, never from argv.
	Authorization string
	// PageLimit, when positive, is sent as the limit parameter; the server
	// may answer with fewer.
	PageLimit int
	// MaxPages and MaxObjects bound the poll; zero takes the defaults.
	MaxPages   int
	MaxObjects int
	// AllowHTTP permits a cleartext http:// collection. Off by default:
	// credentials and the feed itself would travel unprotected, and a feed
	// tampered with in transit is a detection-content supply-chain problem.
	AllowHTTP bool
	// Client overrides the HTTP client (tests, a custom trust store).
	Client *http.Client
}

// TAXIIResult is what one poll returned.
type TAXIIResult struct {
	// Objects are the STIX objects, in the order served.
	Objects []json.RawMessage
	// Pages is the number of envelopes read.
	Pages int
	// LastAdded is the newest X-TAXII-Date-Added-Last the server reported:
	// the AddedAfter value for the next poll. Empty when the server sent none.
	LastAdded string
	// Truncated reports that a bound (pages or objects) ended the poll while
	// the server still had more. The objects read are valid; LastAdded lets
	// the next poll resume after them.
	Truncated bool
}

// Bundle wraps the polled objects as a STIX bundle, the input ParseSTIX takes.
func (r TAXIIResult) Bundle() []byte {
	objs := r.Objects
	if objs == nil {
		objs = []json.RawMessage{}
	}
	b, _ := json.Marshal(struct {
		Type    string            `json:"type"`
		Objects []json.RawMessage `json:"objects"`
	}{"bundle", objs})
	return b
}

type taxiiEnvelope struct {
	More    bool              `json:"more"`
	Next    string            `json:"next"`
	Objects []json.RawMessage `json:"objects"`
}

// taxiiObjectsURL resolves the objects endpoint under a collection URL.
func taxiiObjectsURL(collection string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(collection))
	if err != nil {
		return nil, fmt.Errorf("intake: TAXII collection url: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return nil, errors.New("intake: refusing a cleartext http:// TAXII collection (the feed and any credential would be unprotected in transit)")
		}
	default:
		return nil, fmt.Errorf("intake: TAXII collection url must be https (got scheme %q)", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("intake: TAXII collection url has no host")
	}
	if u.User != nil {
		return nil, errors.New("intake: put TAXII credentials in the authorization variable, not in the url")
	}
	p := strings.TrimRight(u.Path, "/")
	p = strings.TrimSuffix(p, "/objects")
	if !strings.Contains(p, "/collections/") {
		return nil, errors.New("intake: TAXII url must name a collection (…/collections/<id>/)")
	}
	u.Path = p + "/objects/"
	u.RawQuery, u.Fragment = "", ""
	return u, nil
}

// FetchTAXII polls a TAXII 2.1 collection and returns its STIX objects.
func FetchTAXII(ctx context.Context, opts TAXIIOptions) (TAXIIResult, error) {
	var res TAXIIResult
	base, err := taxiiObjectsURL(opts.CollectionURL, opts.AllowHTTP)
	if err != nil {
		return res, err
	}
	if opts.AddedAfter != "" {
		if _, err := time.Parse(time.RFC3339Nano, opts.AddedAfter); err != nil {
			return res, fmt.Errorf("intake: added-after %q is not an RFC 3339 timestamp", opts.AddedAfter)
		}
	}
	maxPages, maxObjects := opts.MaxPages, opts.MaxObjects
	if maxPages <= 0 {
		maxPages = DefaultTAXIIMaxPages
	}
	if maxObjects <= 0 {
		maxObjects = DefaultTAXIIMaxObjects
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	// A redirect off the named host would send the credential, and take the
	// detection content, from somewhere the operator never approved.
	pinned := *client
	pinned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != base.Host || req.URL.Scheme != base.Scheme {
			return fmt.Errorf("refusing a redirect from %s to %s", base.Host, req.URL.Host)
		}
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return nil
	}

	var total int64
	next := ""
	seen := map[string]bool{}
	for {
		q := url.Values{}
		if opts.AddedAfter != "" {
			q.Set("added_after", opts.AddedAfter)
		}
		if opts.PageLimit > 0 {
			q.Set("limit", strconv.Itoa(opts.PageLimit))
		}
		if next != "" {
			q.Set("next", next)
		}
		u := *base
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return res, fmt.Errorf("intake: TAXII build request: %w", err)
		}
		req.Header.Set("Accept", TAXIIMediaType)
		req.Header.Set("User-Agent", "cau-intake")
		if opts.Authorization != "" {
			req.Header.Set("Authorization", opts.Authorization)
		}
		resp, err := pinned.Do(req)
		if err != nil {
			return res, fmt.Errorf("intake: TAXII poll %s: %w", base.Host, redact(err, opts.Authorization))
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes-total+1))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return res, fmt.Errorf("intake: TAXII poll %s: HTTP %d", base.Host, resp.StatusCode)
		}
		if rerr != nil {
			return res, fmt.Errorf("intake: TAXII read %s: %w", base.Host, rerr)
		}
		total += int64(len(body))
		if total > maxFetchBytes {
			return res, fmt.Errorf("intake: TAXII collection at %s exceeds the %d-byte cap; poll with added-after to narrow it", base.Host, maxFetchBytes)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.Contains(strings.ToLower(ct), "json") {
			return res, fmt.Errorf("intake: TAXII poll %s: unexpected content type %q (is this a TAXII 2.1 collection?)", base.Host, ct)
		}
		var env taxiiEnvelope
		if err := json.Unmarshal(body, &env); err != nil {
			return res, fmt.Errorf("intake: TAXII envelope from %s: %w", base.Host, err)
		}
		res.Pages++
		if last := resp.Header.Get(taxiiHeaderLast); last != "" {
			if _, perr := time.Parse(time.RFC3339Nano, last); perr == nil && last > res.LastAdded {
				res.LastAdded = last
			}
		}
		for _, o := range env.Objects {
			if len(res.Objects) >= maxObjects {
				res.Truncated = true
				return res, nil
			}
			res.Objects = append(res.Objects, o)
		}
		if !env.More {
			return res, nil
		}
		if env.Next == "" {
			return res, fmt.Errorf("intake: TAXII server at %s reported more objects but gave no next cursor", base.Host)
		}
		if seen[env.Next] {
			return res, fmt.Errorf("intake: TAXII server at %s repeated a pagination cursor; stopping", base.Host)
		}
		seen[env.Next] = true
		next = env.Next
		if res.Pages >= maxPages {
			res.Truncated = true
			return res, nil
		}
	}
}

// redact removes a credential from an error string.
func redact(err error, secret string) error {
	if secret == "" || !strings.Contains(err.Error(), secret) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), secret, "[redacted]"))
}

// TAXIIState is the polling cursor persisted between runs: which collection
// was polled and how far. It holds no credential.
type TAXIIState struct {
	Collection string `json:"collection"`
	AddedAfter string `json:"added_after"`
	Updated    string `json:"updated,omitempty"`
}

// LoadTAXIIState reads a cursor file. A missing file is an empty cursor (the
// first poll takes the whole collection). A cursor recorded for a different
// collection is an error rather than a silent full or partial re-poll.
func LoadTAXIIState(path, collection string) (TAXIIState, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return TAXIIState{Collection: collection}, nil
	}
	if err != nil {
		return TAXIIState{}, fmt.Errorf("intake: read TAXII state: %w", err)
	}
	var st TAXIIState
	if err := json.Unmarshal(raw, &st); err != nil {
		return TAXIIState{}, fmt.Errorf("intake: TAXII state %s is corrupt: %w", path, err)
	}
	if st.Collection != "" && st.Collection != collection {
		return TAXIIState{}, fmt.Errorf("intake: TAXII state %s belongs to %s, not %s", path, st.Collection, collection)
	}
	if st.AddedAfter != "" {
		if _, err := time.Parse(time.RFC3339Nano, st.AddedAfter); err != nil {
			return TAXIIState{}, fmt.Errorf("intake: TAXII state %s holds a bad timestamp %q", path, st.AddedAfter)
		}
	}
	st.Collection = collection
	return st, nil
}

// SaveTAXIIState writes the cursor atomically (temp file + rename), so an
// interrupted run leaves the previous cursor, never a half-written one.
func SaveTAXIIState(path string, st TAXIIState, now time.Time) error {
	st.Updated = now.UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("intake: encode TAXII state: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".taxii-state-*")
	if err != nil {
		return fmt.Errorf("intake: write TAXII state: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("intake: write TAXII state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("intake: write TAXII state: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("intake: write TAXII state: %w", err)
	}
	return nil
}
