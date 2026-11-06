package netblock

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// TestEveryBackendIsConcurrencySafe exercises both backends under -race.
//
// The nftables path records through one method and was safe once that method
// took the lock; the iptables path has three more recording sites (chain
// creation, a tolerated failure, and a dry run's rendered delete) that the
// first fix missed, because a discovery-based test on a host with nft installed
// never reaches them. Both backends are forced here for that reason.
func TestEveryBackendIsConcurrencySafe(t *testing.T) {
	for _, backend := range []Backend{BackendNFT, BackendIPTables} {
		t.Run(string(backend), func(t *testing.T) {
			fw := newFakeFW("nft", "iptables", "ip6tables", "ss")
			// A tolerated failure, so that recording site is reached too.
			fw.fail["iptables -w -N CAU-OUT"] = errors.New("exit 1")
			fw.out["iptables -w -N CAU-OUT"] = "iptables: Chain already exists."
			fw.fail["iptables -w -S CAU-OUT"] = errors.New("exit 1")
			fw.fail["iptables -w -S CAU-IN"] = errors.New("exit 1")

			b, err := Open(Options{Backend: backend, Run: fw.lockedRun, Look: fw.look, DryRun: true, Sever: true})
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			for i := range 24 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					addr := fmt.Sprintf("198.51.100.%d", i+1)
					if _, err := b.Block(addr, "incident "+addr); err != nil {
						t.Errorf("Block(%s): %v", addr, err)
					}
					_, _ = b.Expire()
					_ = b.Unblock(addr)
					_ = b.Commands()
				}()
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = b.Clear()
			}()
			wg.Wait()

			cmds := b.Commands()
			if len(cmds) == 0 {
				t.Fatal("a dry run must record what it would do")
			}
			// Every recorded line is whole: a torn append would show up as an
			// empty entry or one that is not a command.
			for _, c := range cmds {
				if strings.TrimSpace(c) == "" {
					t.Fatalf("an empty command was recorded among %d", len(cmds))
				}
			}
			blocked := 0
			for _, c := range cmds {
				if strings.Contains(c, "add element") || strings.Contains(c, "-A CAU-OUT") {
					blocked++
				}
			}
			if blocked != 24 {
				t.Errorf("recorded %d blocks, want 24: a lost append means a block nobody can audit", blocked)
			}
		})
	}
}

// lockedRun is the fake firewall's runner made safe for concurrent use: the
// fake's own bookkeeping is not what is under test here.
func (f *fakeFW) lockedRun(name string, args []string, stdin string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.run(name, args, stdin)
}
