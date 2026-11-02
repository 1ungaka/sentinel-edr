package ole

// MS-OVBA CompressedContainer decompression ([MS-OVBA] 2.4.1).
//
// A CompressedContainer is a 0x01 signature byte followed by one or more
// CompressedChunks. Each chunk begins with a 2-byte CompressedChunkHeader:
//
//	bits 0..11  CompressedChunkSize  (chunk length, including this header, minus 3)
//	bits 12..14 CompressedChunkSignature (MUST be 0b011)
//	bit  15     CompressedChunkFlag  (1 = token-compressed, 0 = raw 4096-byte chunk)
//
// A compressed chunk is a run of TokenSequences, each a 1-byte FlagByte followed
// by up to 8 tokens. A clear flag bit is a 1-byte literal; a set bit is a 2-byte
// CopyToken whose Length/Offset split depends on the current offset WITHIN the
// chunk's decompressed output (CopyTokenHelp). Each chunk decompresses to at
// most 4096 bytes, and copy offsets never reference earlier chunks.
//
// This decompressor is defensive: it caps total output, bounds every chunk to
// 4096 bytes, tolerates truncation, and STOPS cleanly at the first chunk whose
// signature is not 0b011 (which is how it ignores any padding that follows a
// container embedded in a larger stream). It never panics.

// maxDecompressed caps a single container's total decompressed output.
const maxDecompressed = 16 << 20

// chunkDecompressedMax is the per-chunk decompressed-output limit from the spec.
const chunkDecompressedMax = 4096

// DecompressContainer decompresses an [MS-OVBA] CompressedContainer. It returns
// the decompressed bytes and ok=true when at least one byte was produced; a
// buffer that does not start with the 0x01 signature, or that yields nothing,
// returns (nil, false). It never panics. Output is capped at maxDecompressed.
func DecompressContainer(data []byte) ([]byte, bool) {
	return decompressContainer(data, maxDecompressed)
}

// decompressContainer is DecompressContainer with an explicit output cap, so a
// caller scanning many candidate offsets can bound its total decompression work.
func decompressContainer(data []byte, limit int) ([]byte, bool) {
	if len(data) < 1 || data[0] != 0x01 {
		return nil, false
	}
	if limit > maxDecompressed {
		limit = maxDecompressed
	}
	if limit <= 0 {
		return nil, false
	}
	out := make([]byte, 0, chunkDecompressedMax)
	pos := 1
	for pos+2 <= len(data) {
		header := uint16(data[pos]) | uint16(data[pos+1])<<8
		pos += 2

		chunkSignature := (header >> 12) & 0x07
		if chunkSignature != 0b011 {
			break // not a valid chunk header — end of the container (or padding)
		}
		compressed := (header>>15)&1 == 1
		chunkLen := int(header&0x0FFF) + 3 // total chunk length, header included
		dataLen := chunkLen - 2
		if dataLen <= 0 {
			break
		}
		chunkEnd := pos + dataLen
		if chunkEnd > len(data) {
			chunkEnd = len(data) // tolerate a truncated final chunk
		}

		chunkStart := len(out) // decompressed offset of this chunk's first byte
		if compressed {
			decompressChunk(data[pos:chunkEnd], &out, chunkStart, limit)
		} else {
			n := chunkEnd - pos
			if len(out)+n > limit {
				n = limit - len(out)
			}
			if n > 0 {
				out = append(out, data[pos:pos+n]...)
			}
		}

		pos = chunkEnd
		if len(out) >= limit {
			break
		}
	}
	return out, len(out) > 0
}

// decompressChunk expands one token-compressed chunk into out. It is bounded to
// chunkDecompressedMax bytes of chunk output and to the caller's total limit, and
// tolerates truncation by returning early. It never panics.
func decompressChunk(in []byte, out *[]byte, chunkStart, limit int) {
	i := 0
	for i < len(in) {
		flagByte := in[i]
		i++
		for bit := 0; bit < 8; bit++ {
			if i >= len(in) {
				return // ran out mid-sequence
			}
			if (flagByte>>uint(bit))&1 == 0 {
				// LiteralToken: one byte copied verbatim.
				*out = append(*out, in[i])
				i++
			} else {
				// CopyToken: 2 bytes, split per CopyTokenHelp.
				if i+2 > len(in) {
					return
				}
				token := uint16(in[i]) | uint16(in[i+1])<<8
				i += 2

				diff := len(*out) - chunkStart
				if diff <= 0 {
					return // a copy cannot be the first thing in a chunk
				}
				bitCount := 4
				for (1 << uint(bitCount)) < diff {
					bitCount++
				}
				lengthMask := uint16(0xFFFF) >> uint(bitCount)
				offsetMask := ^lengthMask
				length := int(token&lengthMask) + 3
				offset := int((token&offsetMask)>>uint(16-bitCount)) + 1

				src := len(*out) - offset
				if src < 0 {
					return // offset points before the chunk / buffer
				}
				for k := 0; k < length; k++ {
					if len(*out) >= limit || len(*out)-chunkStart >= chunkDecompressedMax {
						return
					}
					*out = append(*out, (*out)[src+k])
				}
			}
			if len(*out) >= limit || len(*out)-chunkStart >= chunkDecompressedMax {
				return
			}
		}
	}
}
