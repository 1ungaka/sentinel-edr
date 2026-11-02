package lnk

import (
	"encoding/binary"
	"testing"
)

// FuzzAnalyze drives the .lnk parser and detector with mutated input. The
// parser reads untrusted, attacker-controlled sizes (IDList size, LinkInfo
// size, per-string CountCharacters, ExtraData block sizes) through a
// bounds-checked cursor; the invariant is that Analyze never panics and always
// returns a non-nil result, however truncated or adversarial the bytes are.
// Seeds cover an empty buffer, a valid synthetic shortcut, truncated headers,
// random bytes, and headers that declare enormous IDList / string / block
// sizes to probe the bounds checks.
func FuzzAnalyze(f *testing.F) {
	valid := buildLNK(lnkSpec{
		unicode: true, hasName: true, hasArgs: true, name: "doc",
		args: "powershell.exe -nop -w hidden -enc QQBBAEEA",
	})

	// A header that claims a huge LinkTargetIDList but supplies no bytes.
	hugeIDList := append([]byte(nil), valid[:headerSize]...)
	binary.LittleEndian.PutUint32(hugeIDList[20:], flagHasLinkTargetIDList|flagIsUnicode)
	hugeIDList = append(hugeIDList, u16b(0xFFFF)...)

	// A header with HasArguments and a string count of 0xFFFF but no data.
	hugeString := append([]byte(nil), valid[:headerSize]...)
	binary.LittleEndian.PutUint32(hugeString[20:], flagHasArguments)
	hugeString = append(hugeString, u16b(0xFFFF)...)

	// A header with HasLinkInfo claiming a 4 GiB LinkInfo block.
	hugeLinkInfo := append([]byte(nil), valid[:headerSize]...)
	binary.LittleEndian.PutUint32(hugeLinkInfo[20:], flagHasLinkInfo)
	hugeLinkInfo = append(hugeLinkInfo, u32b(0xFFFFFFFF)...)

	// A valid shortcut with an ExtraData block that overruns the file.
	hugeBlock := append([]byte(nil), valid...)
	hugeBlock = append(hugeBlock[:len(hugeBlock)-4], u32b(0x7FFFFFFF)...) // overwrite terminal with a giant block size
	hugeBlock = append(hugeBlock, u32b(sigEnvironmentVariable)...)

	seeds := [][]byte{
		{},
		[]byte("not a shortcut"),
		valid,
		valid[:20], // just the identity bytes
		valid[:40], // truncated header body
		valid[:headerSize],
		hugeIDList,
		hugeString,
		hugeLinkInfo,
		hugeBlock,
		buildLNK(lnkSpec{hasName: true, name: "x", trailing: 2048}),
		buildLNK(lnkSpec{hasName: true, name: "x", omitTerminal: true}),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := Analyze(data, Options{})
		if r == nil {
			t.Fatal("Analyze returned nil")
		}
		// A non-Shell-Link buffer must stay a clean zero-score result.
		if !IsLNK(data) {
			if r.Score != 0 || len(r.Findings) != 0 {
				t.Fatalf("non-LNK buffer produced findings: %+v", r)
			}
			return
		}
		// The reported score must equal the sum of the finding weights.
		sum := 0
		for _, fnd := range r.Findings {
			sum += fnd.Score
		}
		if sum != r.Score {
			t.Fatalf("score %d does not match finding sum %d: %+v", r.Score, sum, r.Findings)
		}
	})
}
