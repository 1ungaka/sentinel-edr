package forward

import (
	"context"

	"github.com/s-b-repo/cau/internal/forward/wazuh"
)

// WazuhSender adapts a Wazuh Manager client to Sender, so the daemon forwards
// through exactly the client `cau scan --wazuh-url` uses: one transport, one set
// of TLS and auth decisions, nothing for the two paths to disagree about.
type WazuhSender struct {
	Client *wazuh.Client
}

// Send posts the batch and reports what the manager took. A partial delivery
// returns both the count and the error, which is what lets the sink resend only
// the tail instead of duplicating the events that landed.
func (w WazuhSender) Send(ctx context.Context, events []map[string]any) (int, error) {
	res := w.Client.Send(ctx, events)
	return res.Delivered, res.Err
}

// WazuhBatch is the manager's own per-request limit, so the sink batches to the
// size the transport will actually send in one POST.
const WazuhBatch = wazuh.MaxEventsPerRequest
