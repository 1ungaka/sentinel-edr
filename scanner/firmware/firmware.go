// Package firmware looks inside a firmware image.
//
// A router, NAS or IoT image is a container: a filesystem, an archive or a
// compressed stream with the real content somewhere inside it. Scanning the
// image as one blob finds the container's bytes and nothing else. This package
// finds the containers — squashfs, cramfs, jffs2, ext, FAT, gzip, zip, tar,
// xz, zstd, LZMA, uImage, ISO — and extracts the members of the formats the
// engine can already read, so the ordinary detectors can run over what is
// inside rather than over the image as a whole.
//
// What it does not do is guess. A container it cannot open is reported with
// its offset and the reason it was not opened, never as an empty result: a
// firmware image whose filesystem was not unpacked is an image nothing was
// measured in.
package firmware

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

// Limits bound what one look inside may cost. A firmware image is
// operator-supplied content, and the extraction must not be a way to make the
// engine allocate without limit.
type Limits struct {
	// MaxContainers caps how many containers are reported.
	MaxContainers int
	// MaxMembers caps how many members are extracted.
	MaxMembers int
	// MaxMemberBytes caps one extracted member.
	MaxMemberBytes int64
	// MaxTotalBytes caps everything extracted together.
	MaxTotalBytes int64
}

// DefaultLimits are the bounds the command uses.
func DefaultLimits() Limits {
	return Limits{
		MaxContainers:  64,
		MaxMembers:     512,
		MaxMemberBytes: 16 << 20,
		MaxTotalBytes:  256 << 20,
	}
}

// Container is one filesystem or archive found inside an image.
type Container struct {
	// Format is the container's name ("squashfs", "gzip", "zip", ...).
	Format string `json:"format"`
	// Offset is where the container starts in the image.
	Offset int64 `json:"offset"`
	// Size is the container's length when it is known, 0 when it is not.
	Size int64 `json:"size,omitempty"`
	// Opened says whether the container's members were extracted.
	Opened bool `json:"opened"`
	// Members is how many members were extracted from it.
	Members int `json:"members,omitempty"`
	// Note says what was not opened and why.
	Note string `json:"note,omitempty"`
}

// Member is one extracted file.
type Member struct {
	// Container is the container the member came from.
	Container string `json:"container"`
	// Path is the member's path inside the container.
	Path string `json:"path"`
	// Size is the member's length.
	Size int64 `json:"size"`
	// Data is the member's content.
	Data []byte `json:"-"`
}

// Image is the result of looking inside one image.
type Image struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	// Containers are the containers found, in the order they appear.
	Containers []Container `json:"containers"`
	// Members are the extracted files.
	Members []Member `json:"members"`
	// Truncated says a cap stopped the work: more containers or members
	// exist than are reported.
	Truncated bool `json:"truncated,omitempty"`
	// Notes carry what could not be done.
	Notes []string `json:"notes,omitempty"`
}

// magic is one container signature.
type magic struct {
	format string
	// pattern is the signature.
	pattern []byte
	// at is where the signature sits inside the container (0 for the start,
	// 257 for a tar header, 1080 for an ext superblock, 0x8001 for an ISO).
	at int64
	// note says why the container is not opened.
	note string
}

// magics are the container signatures this package knows.
//
// The offsets are the signatures' places inside their container: a tar's
// "ustar" sits 257 bytes into the archive, an ext superblock's magic sits at
// 1080, an ISO's at 0x8001. A signature found at position i therefore marks a
// container that starts at i - at.
var magics = []magic{
	{format: "squashfs", pattern: []byte("hsqs")},
	{format: "squashfs", pattern: []byte("sqsh")},
	{format: "cramfs", pattern: []byte{0x45, 0x3d, 0xcd, 0x28}},
	{format: "jffs2", pattern: []byte{0x85, 0x19}},
	{format: "gzip", pattern: []byte{0x1f, 0x8b}},
	{format: "zip", pattern: []byte("PK\x03\x04")},
	{format: "xz", pattern: []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}},
	{format: "zstd", pattern: []byte{0x28, 0xb5, 0x2f, 0xfd}},
	{format: "lzma", pattern: []byte{0x5d, 0x00, 0x00}},
	{format: "uImage", pattern: []byte{0x27, 0x05, 0x19, 0x56}},
	{format: "ext2/3/4", pattern: []byte{0x53, 0xef}, at: 1080},
	{format: "iso", pattern: []byte("CD001"), at: 0x8001},
	{format: "tar", pattern: []byte("ustar"), at: 257},
	{format: "fat", pattern: []byte("FAT")},
}

// Analyze looks inside an image and extracts what it can.
//
// The image is read, never executed, and the members are handed back as
// bytes: what happens to them is the caller's business.
func Analyze(data []byte, path string, limits Limits) *Image {
	if limits.MaxContainers <= 0 {
		limits = DefaultLimits()
	}
	img := &Image{Path: path, Size: int64(len(data))}
	seen := map[string]bool{}
	total := int64(0)

	for _, m := range magics {
		for off := 0; off < len(data); {
			i := bytes.Index(data[off:], m.pattern)
			if i < 0 {
				break
			}
			pos := int64(off + i)
			off += i + 1
			start := pos - m.at
			if start < 0 {
				continue
			}
			key := fmt.Sprintf("%s@%d", m.format, start)
			if seen[key] {
				continue
			}
			seen[key] = true
			if len(img.Containers) >= limits.MaxContainers {
				img.Truncated = true
				img.Notes = append(img.Notes, fmt.Sprintf("more than %d containers in the image; the rest are not listed", limits.MaxContainers))
				break
			}
			c := Container{Format: m.format, Offset: start, Note: m.note}
			members, skipped, err := extract(data, m.format, start, limits, &total)
			switch {
			case err != nil && !errors.Is(err, errNotOpenable):
				c.Note = err.Error()
			case err == nil:
				c.Opened = true
				c.Members = len(members)
				for _, mem := range members {
					img.Members = append(img.Members, mem)
				}
				if skipped > 0 {
					// A member that could not be read is a coverage gap, and
					// it is said so rather than counted as an empty member.
					c.Note = fmt.Sprintf("%d member(s) could not be read", skipped)
				}
			}
			if !c.Opened && c.Note == "" {
				c.Note = "this container format is identified but not opened by this build"
			}
			img.Containers = append(img.Containers, c)
		}
	}

	sort.SliceStable(img.Containers, func(i, j int) bool {
		if img.Containers[i].Offset != img.Containers[j].Offset {
			return img.Containers[i].Offset < img.Containers[j].Offset
		}
		return img.Containers[i].Format < img.Containers[j].Format
	})
	return img
}

// errNotOpenable says the container was found and nothing was read out of it.
var errNotOpenable = fmt.Errorf("the container format is identified but not opened by this build")

// extract reads the members out of a container at the given offset.
func extract(data []byte, format string, start int64, limits Limits, total *int64) ([]Member, int, error) {
	switch format {
	case "gzip":
		m, err := extractGzip(data, start, limits, total)
		return m, 0, err
	case "zip":
		m, skipped, err := extractZip(data, start, limits, total)
		return m, skipped, err
	case "tar":
		m, skipped, err := extractTar(data, start, limits, total)
		return m, skipped, err
	}
	return nil, 0, errNotOpenable
}

// extractGzip inflates one gzip member and reports where it ended.
func extractGzip(data []byte, start int64, limits Limits, total *int64) ([]Member, error) {
	if start >= int64(len(data)) {
		return nil, fmt.Errorf("the gzip member starts past the end of the image")
	}
	zr, err := gzip.NewReader(bytes.NewReader(data[start:]))
	if err != nil {
		return nil, fmt.Errorf("the gzip member does not open: %w", err)
	}
	defer zr.Close()
	// One member, not a stream: the bytes after the member in an image are
	// the next thing in the image, not a second gzip member.
	zr.Multistream(false)
	out, err := io.ReadAll(io.LimitReader(zr, limits.MaxMemberBytes+1))
	if err != nil {
		return nil, fmt.Errorf("the gzip member does not inflate: %w", err)
	}
	if int64(len(out)) > limits.MaxMemberBytes {
		return nil, fmt.Errorf("the gzip member is larger than the %d byte member budget", limits.MaxMemberBytes)
	}
	if *total+int64(len(out)) > limits.MaxTotalBytes {
		return nil, fmt.Errorf("the extraction budget of %d bytes is spent", limits.MaxTotalBytes)
	}
	*total += int64(len(out))
	return []Member{{Container: "gzip", Path: fmt.Sprintf("gzip@%d", start), Size: int64(len(out)), Data: out}}, nil
}

// extractZip reads the members of one zip archive.
//
// The archive's own bounds are found from its end-of-central-directory record:
// the directory sits at a known distance from the end, which is what makes an
// archive embedded in an image readable without knowing where it starts.
func extractZip(data []byte, start int64, limits Limits, total *int64) ([]Member, int, error) {
	end, err := zipEnd(data, start)
	if err != nil {
		return nil, 0, err
	}
	slice := data[start:end]
	zr, err := zip.NewReader(bytes.NewReader(slice), int64(len(slice)))
	if err != nil {
		return nil, 0, fmt.Errorf("the zip archive does not open: %w", err)
	}
	var out []Member
	skipped := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if len(out) >= limits.MaxMembers {
			break
		}
		rc, err := f.Open()
		if err != nil {
			skipped++
			continue
		}
		content, err := io.ReadAll(io.LimitReader(rc, limits.MaxMemberBytes+1))
		rc.Close()
		if err != nil {
			skipped++
			continue
		}
		if int64(len(content)) > limits.MaxMemberBytes {
			skipped++
			continue
		}
		if *total+int64(len(content)) > limits.MaxTotalBytes {
			return out, skipped, fmt.Errorf("the extraction budget of %d bytes is spent", limits.MaxTotalBytes)
		}
		*total += int64(len(content))
		out = append(out, Member{Container: "zip", Path: f.Name, Size: int64(len(content)), Data: content})
	}
	return out, skipped, nil
}

// zipEnd finds where the zip archive that starts at start ends.
//
// The end-of-central-directory record is the last one in the image that
// carries the "PK\x05\x06" signature and a comment length that reaches the
// end of the image, so a zip embedded in a larger file is found rather than
// guessed at.
func zipEnd(data []byte, start int64) (int64, error) {
	const sig = "PK\x05\x06"
	for i := len(data) - 22; i >= int(start); i-- {
		if !bytes.HasPrefix(data[i:], []byte(sig)) {
			continue
		}
		commentLen := int64(binary.LittleEndian.Uint16(data[i+20 : i+22]))
		if int64(i)+22+commentLen != int64(len(data)) {
			continue
		}
		cdSize := int64(binary.LittleEndian.Uint32(data[i+12 : i+16]))
		cdOff := int64(binary.LittleEndian.Uint32(data[i+16 : i+20]))
		// The directory sits at cdOff from the archive's start and is cdSize
		// long, and the record is 22 bytes plus its comment long.
		archiveStart := int64(i) - cdSize - cdOff
		if archiveStart < start {
			// The offsets are relative to something else (a zip written
			// with absolute offsets): fall back to the signature's own
			// position.
			archiveStart = start
		}
		return int64(i) + 22 + commentLen, nil
	}
	return 0, fmt.Errorf("the zip archive has no end-of-central-directory record")
}

// extractTar reads the members of one tar archive.
func extractTar(data []byte, start int64, limits Limits, total *int64) ([]Member, int, error) {
	slice := data[start:]
	tr := tar.NewReader(bytes.NewReader(slice))
	var out []Member
	skipped := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if len(out) == 0 {
				return nil, 0, fmt.Errorf("the tar archive does not read: %w", err)
			}
			skipped++
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if len(out) >= limits.MaxMembers {
			break
		}
		content, err := io.ReadAll(io.LimitReader(tr, limits.MaxMemberBytes+1))
		if err != nil {
			skipped++
			continue
		}
		if int64(len(content)) > limits.MaxMemberBytes {
			skipped++
			continue
		}
		if *total+int64(len(content)) > limits.MaxTotalBytes {
			return out, skipped, fmt.Errorf("the extraction budget of %d bytes is spent", limits.MaxTotalBytes)
		}
		*total += int64(len(content))
		out = append(out, Member{Container: "tar", Path: hdr.Name, Size: int64(len(content)), Data: content})
	}
	if len(out) == 0 {
		return nil, skipped, fmt.Errorf("the tar archive holds no regular files")
	}
	return out, skipped, nil
}
