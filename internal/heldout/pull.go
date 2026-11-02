package heldout

import (
	"archive/zip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// MalwareBazaar CSV exports. "full" is the entire dataset; "recent" is the
// last few days, for a fast incremental top-up. Both are the same column
// layout and need no API key.
const (
	MBFullCSV   = "https://bazaar.abuse.ch/export/csv/full/"
	MBRecentCSV = "https://bazaar.abuse.ch/export/csv/recent/"
	mbSampleURL = "https://bazaar.abuse.ch/sample/"
)

// PullOptions tunes a feed pull. The zero value pulls the full MalwareBazaar
// export, checkpointing every 20,000 new records.
type PullOptions struct {
	// URL is the CSV (zip) export to pull; defaults to MBFullCSV.
	URL string
	// Cache is where the downloaded zip is stored so an interrupted pull
	// resumes the download instead of restarting it. Defaults to a temp file.
	Cache string
	// Client is the HTTP client (injectable for tests). Defaults to a client
	// with a generous timeout disabled in favour of per-attempt context.
	Client *http.Client
	// Batch is how many NEW records to accept between checkpoints. A
	// checkpoint re-encrypts and saves the whole database, so this trades
	// durability against speed. Defaults to 20,000.
	Batch int
	// Limit, when > 0, stops after adding this many new records.
	Limit int
	// Family, when set, keeps only rows whose signature matches (case-insensitive).
	Family string
	// Retries is the number of download attempts before giving up (with
	// exponential backoff between them). Defaults to 5.
	Retries int
	// Progress, when set, is called roughly once per batch with running totals.
	Progress func(added, seen int)
	// now is injectable for tests.
	now func() time.Time
}

func (o *PullOptions) defaults() {
	if o.URL == "" {
		o.URL = MBFullCSV
	}
	if o.Client == nil {
		o.Client = &http.Client{}
	}
	if o.Batch <= 0 {
		o.Batch = 20_000
	}
	if o.Retries <= 0 {
		o.Retries = 5
	}
	if o.now == nil {
		o.now = time.Now
	}
}

// PullStats reports what a pull did.
type PullStats struct {
	Seen       int // data rows read
	Added      int // new records inserted
	Updated    int // existing hashes whose intel was refreshed
	Downloaded int64
	Resumed    bool
}

// Pull downloads a feed export (resuming a partial download when it can),
// streams its CSV, and ingests the rows into db, calling save to checkpoint
// the encrypted database every Batch new records and once at the end. It is
// safe to re-run: present hashes are skipped, so a crashed pull picks up where
// the last checkpoint left it. save must persist db durably (e.g. encrypt to
// a temp file and rename).
func Pull(ctx context.Context, db *DB, save func(*DB) error, opts PullOptions) (PullStats, error) {
	opts.defaults()
	var stats PullStats

	cache := opts.Cache
	cleanup := func() {}
	if cache == "" {
		tmp, err := os.CreateTemp("", "cau-heldout-*.zip")
		if err != nil {
			return stats, err
		}
		tmp.Close()
		cache = tmp.Name()
		cleanup = func() { os.Remove(cache) }
	}
	defer cleanup()

	n, resumed, err := downloadResumable(ctx, opts.URL, cache, opts.Client, opts.Retries, opts.now)
	if err != nil {
		return stats, fmt.Errorf("heldout pull: download: %w", err)
	}
	stats.Downloaded = n
	stats.Resumed = resumed

	zr, err := zip.OpenReader(cache)
	if err != nil {
		return stats, fmt.Errorf("heldout pull: open export: %w", err)
	}
	defer zr.Close()
	var csvFile *zip.File
	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".csv") {
			csvFile = f
			break
		}
	}
	if csvFile == nil {
		return stats, errors.New("heldout pull: no .csv in the export archive")
	}
	rc, err := csvFile.Open()
	if err != nil {
		return stats, err
	}
	defer rc.Close()

	return ingestCSV(ctx, rc, db, save, &opts, stats)
}

// ingestCSV parses a MalwareBazaar-format CSV and feeds rows into db. Split
// from Pull so the ingest path is testable without a network or a zip.
func ingestCSV(ctx context.Context, r io.Reader, db *DB, save func(*DB) error, opts *PullOptions, stats PullStats) (PullStats, error) {
	cr := csv.NewReader(r)
	cr.Comma = ','
	cr.Comment = '#'        // MB prefixes its header block with '#'
	cr.LazyQuotes = true    // some file names contain stray quotes
	cr.FieldsPerRecord = -1 // tolerate rows with extra tag columns
	cr.TrimLeadingSpace = true

	sinceCheckpoint := 0
	flush := func() error {
		if sinceCheckpoint == 0 {
			return nil
		}
		if err := save(db); err != nil {
			return fmt.Errorf("heldout pull: checkpoint: %w", err)
		}
		sinceCheckpoint = 0
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			_ = flush()
			return stats, ctx.Err()
		default:
		}
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A single malformed row should not abandon a multi-million-row
			// pull; skip it and keep going.
			if _, ok := err.(*csv.ParseError); ok {
				continue
			}
			_ = flush()
			return stats, err
		}
		row, ok := parseMBRow(rec)
		if !ok {
			continue
		}
		stats.Seen++

		if opts.Family != "" && !strings.EqualFold(row.Signature, opts.Family) {
			continue
		}
		sha, err := normSHA(row.SHA256)
		if err != nil {
			continue // not a sha256 row (e.g. a header)
		}
		existed := db.Has(sha)
		if err := db.Add(row); err != nil {
			continue
		}
		if existed {
			stats.Updated++
			continue
		}
		stats.Added++
		sinceCheckpoint++
		if opts.Progress != nil {
			opts.Progress(stats.Added, stats.Seen)
		}
		if sinceCheckpoint >= opts.Batch {
			if err := flush(); err != nil {
				return stats, err
			}
		}
		if opts.Limit > 0 && stats.Added >= opts.Limit {
			break
		}
	}
	if err := flush(); err != nil {
		return stats, err
	}
	return stats, nil
}

// MalwareBazaar full.csv column order.
const (
	mbFirstSeen = 0
	mbSHA256    = 1
	mbReporter  = 4
	mbFileType  = 6
	mbSignature = 8
	mbImphash   = 11
	mbTags      = 13
	mbMinCols   = 9 // through the signature column
)

// parseMBRow maps a CSV record to a Record, returning false for a row that is
// too short or lacks a hash.
func parseMBRow(rec []string) (Record, bool) {
	if len(rec) < mbMinCols {
		return Record{}, false
	}
	get := func(i int) string {
		if i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}
	sig := strings.ToLower(get(mbSignature))
	family := sig
	if family == "" {
		family = "unknown"
	}
	var tags []string
	if t := get(mbTags); t != "" {
		for _, p := range strings.Split(t, ",") {
			if p = strings.TrimSpace(p); p != "" {
				tags = append(tags, p)
			}
		}
	}
	sha := strings.ToLower(get(mbSHA256))
	return Record{
		SHA256:    sha,
		Family:    family,
		Signature: sig,
		Tags:      tags,
		FileType:  get(mbFileType),
		FirstSeen: get(mbFirstSeen),
		Reporter:  get(mbReporter),
		Imphash:   get(mbImphash),
		URL:       mbSampleURL + sha + "/",
		License:   "CC0-1.0",
	}, true
}

// downloadResumable fetches url into dest, resuming a partial dest with a
// Range request and retrying transient failures with exponential backoff. It
// returns the total bytes now on disk and whether the download was resumed.
func downloadResumable(ctx context.Context, url, dest string, client *http.Client, retries int, now func() time.Time) (int64, bool, error) {
	var lastErr error
	backoff := 500 * time.Millisecond
	for attempt := 0; attempt < retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return 0, false, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
		n, resumed, err := downloadOnce(ctx, url, dest, client)
		if err == nil {
			return n, resumed, nil
		}
		lastErr = err
	}
	return 0, false, lastErr
}

func downloadOnce(ctx context.Context, url, dest string, client *http.Client) (int64, bool, error) {
	var have int64
	if fi, err := os.Stat(dest); err == nil {
		have = fi.Size()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false, err
	}
	resumed := false
	if have > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", have))
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()

	var f *os.File
	switch resp.StatusCode {
	case http.StatusPartialContent: // 206: server honoured the Range
		resumed = true
		f, err = os.OpenFile(dest, os.O_WRONLY|os.O_APPEND, 0o600)
	case http.StatusOK: // 200: full body; (re)start the file
		have = 0
		f, err = os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	case http.StatusRequestedRangeNotSatisfiable: // 416: already complete
		return have, true, nil
	default:
		return 0, false, fmt.Errorf("unexpected status %s", resp.Status)
	}
	if err != nil {
		return 0, false, err
	}
	defer f.Close()

	written, err := io.Copy(f, resp.Body)
	if err != nil {
		return have + written, resumed, err // partial; a retry resumes from here
	}
	return have + written, resumed, nil
}
