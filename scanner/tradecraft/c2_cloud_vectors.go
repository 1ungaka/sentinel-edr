package tradecraft

// This file extends the third-party-channel detection with the LOLC2 /
// LOLFSaaS / LOTWebhooks / LOTTunnels catalogues (lolol.farm):
//
//   - 56 abused SaaS services from lolc2.github.io, each with the specific
//     URL paths a known C2 agent calls (graph.microsoft.com/v1.0/me/sendMail,
//     firebaseio.com/.../.json, hooks.zapier.com, api.dropboxapi.com/content,
//     and so on).
//
//   - 41 webhook destinations from lotwebhooks.github.io.
//
//   - 92 tunnel hostnames from lottunnels.github.io's domains.csv.
//
//   - 127 cloud-SaaS hosts from lolfsaas.github.io's data.json, used as
//     trusted-domain C2 fronts.
//
// Two classes carry these:
//
//   - classC2Service (score 3) fires on the host alone. The signal is low
//     because almost every one of these hosts also carries legitimate
//     traffic, so it corroborates another finding rather than convicts.
//
//   - classC2APIAbuse (score 5) fires on a specific abusable API path --
//     Graph mail/drive write, Firebase realtime DB write, Dropbox content
//     upload, Google Apps Script exec, Lambda invoke, a GitHub Contents PUT,
//     a blockchain RPC endpoint. The path is the giveaway: no browser hits
//     these programmatically.
//
// Each vector carries a distinctive lowercase hint that the walker tests
// before running the regex, so adding ~120 vectors stays cheap.

func init() {
	vectors = append(vectors, saasChannelVectors...)
	vectors = append(vectors, saasAPIVectors...)
}

// saasChannelVectors: host-only matches. Each names a known-abused SaaS /
// webhook / tunnel / paste / file-drop / out-of-band interaction service.
// A hit alone cannot cross threshold; it corroborates another finding.
var saasChannelVectors = []vector{
	// ── Chat & collaboration platforms used as C2 (from LOLC2 + LOTWebhooks) ──
	v(classC2Service, "telegram", `\bapi\.telegram\.org/bot\w+/(?:sendMessage|sendDocument|sendPhoto|getUpdates|getMe|getFile)\b|\bt\.me/s/\w`),
	v(classC2Service, "discord", `\bcdn\.discordapp\.com/attachments/\d+/\d+/|\bdiscord\.com/api/(?:v\d+/)?(?:channels|guilds|webhooks|users/@me)\b`),
	v(classC2Service, "slack", `\bslack\.com/api/(?:chat\.postMessage|files\.upload|conversations\.(?:list|history)|rtm\.connect)\b|\bslack-files\.com/\b`),
	v(classC2Service, "microsoft teams", `\bteams\.microsoft\.com/(?:_#|l/)\b`),
	v(classC2Service, "mattermost", `\bmattermost\.(?:com|cloud)/api/v4/(?:posts|files|channels|teams|users)\b`),
	v(classC2Service, "matrix", `\bmatrix\.(?:org|to)/(?:_matrix/client/|#)\b|\bmatrix-client\.matrix\.org\b`),
	v(classC2Service, "zulip", `\.zulipchat\.com/api/v1/(?:messages|register|events|users)\b`),
	v(classC2Service, "zoom", `\bapi\.zoom\.us/v\d+/(?:users|meetings|chat|accounts|phone)/`),
	v(classC2Service, "webex", `\bwebexapis\.com/v\d+/(?:messages|rooms|people|memberships)\b`),

	// ── Code & content platforms used as dead-drop or control plane ──
	// A raw GitHub fetch *from code* is much higher signal than a documentation
	// link, so one of a few programmatic-fetch hints must be present on the
	// same line/region.
	v(classC2Service, "github", `\bapi\.github\.com/repos/[\w.-]+/[\w.-]+/(?:contents|releases/latest|issues/\d+/comments|git/refs)\b`),
	// The endpoints a script fetches from. A gist's web page is what a code
	// comment cites as a reference (measured: scapy), so it is not one.
	v(classC2Service, "gist", `\bapi\.github\.com/gists/|\bgist\.githubusercontent\.com/[\w.-]+/[0-9a-f]{20}\b`),
	v(classC2Service, "raw.githubusercontent", `\braw\.githubusercontent\.com/[\w.-]+/[\w.-]+/[\w./-]+`),
	v(classC2Service, "gitlab", `\bgitlab\.com/api/v\d+/(?:snippets|projects/\d+/(?:repository/files|snippets|issues/\d+/notes))\b`),
	v(classC2Service, "bitbucket", `\bapi\.bitbucket\.org/\d+\.\d+/(?:snippets|repositories/[\w-]+/[\w-]+/(?:src|downloads))\b`),
	v(classC2Service, "pastebin", `\bpastebin\.com/(?:raw|api)/`),
	v(classC2Service, "npm", `\bregistry\.npmjs\.org/[\w@./-]+/-/[\w./-]+\.tgz`),
	v(classC2Service, "notion", `\bapi\.notion\.com/v\d+/(?:databases|pages|blocks)\b|\.notion\.site/\b`),
	v(classC2Service, "trello", `\bapi\.trello\.com/\d+/(?:boards|lists|cards|tokens/[\w-]+/webhooks)\b`),
	v(classC2Service, "asana", `\bapp\.asana\.com/api/\d+\.\d+/`),
	v(classC2Service, ".atlassian.net", `\.atlassian\.net/rest/api/(?:2|3)/(?:issue|comment|attachment)\b`),
	v(classC2Service, "virustotal", `\bwww\.virustotal\.com/api/v\d+/(?:files|urls|comments|intelligence)\b`),
	v(classC2Service, "splunk", `\bhec\.splunk\b|\bsplunkcloud\.com/services/collector\b`),

	// ── Trusted-cloud fronts (LOLFSaaS) used as C2 / payload hosts ──
	v(classC2APIAbuse, ".firebaseio.com", `\b[\w.-]*\.firebaseio\.com/(?:agents|tasks|results|files|uploads|upload_results)/[\w./-]*\.json`),
	v(classC2APIAbuse, "firebaseapp", `\b[\w.-]*\.firebaseapp\.com/|\b[\w.-]*\.web\.app/|firebasestorage\.googleapis\.com/v\d+/b/`),
	v(classC2APIAbuse, "azurewebsites", `\b[\w.-]*\.azurewebsites\.net/api/[\w-]+(?:\?code=\S+)?`),
	v(classC2APIAbuse, "workers.dev", `\b[\w.-]+\.workers\.dev/[\w./-]+`),
	v(classC2APIAbuse, "pages.dev", `\b[\w.-]+\.pages\.dev/[\w./-]+`),
	v(classC2APIAbuse, "msappproxy", `\b[\w.-]+\.msappproxy\.net/`),
	v(classC2APIAbuse, ".appspot.com", `\b[\w.-]+\.appspot\.com/[\w./-]+`),
	v(classC2APIAbuse, "cloudfront", `\b[\w.-]+\.cloudfront\.net/[\w./-]*(?:\.(?:php|aspx?|jsp|cfm)|\?cmd=|\?c=|/beacon)`),
	v(classC2APIAbuse, "s3.amazonaws", `\bs3\.amazonaws\.com/[\w.-]+/|\b[\w.-]+\.s3[.\-]\w*amazonaws\.com/`),
	v(classC2APIAbuse, "lambda", `\blambda\.[\w.-]+\.amazonaws\.com/2015-03-31/functions/[\w.-]+/invocations`),
	v(classC2APIAbuse, "blob.core.windows", `\b[\w.-]+\.blob\.core\.windows\.net/[\w./-]+`),
	v(classC2APIAbuse, "herokuapp", `\b[\w.-]+\.herokuapp\.com/[\w./-]+`),

	// ── Microsoft Graph abuse surface ──
	v(classC2APIAbuse, "graph.microsoft", `\bgraph\.microsoft\.com/(?:v1\.0|beta)/(?:me/(?:messages|sendMail|drive/root|MailFolders|chats)|users/[^/]+/(?:messages|sendMail|drive/|mailFolders)|drives/[^/]+/items/[^/]+/(?:content|workbook)|sites/[^/]+/(?:drives|drive/items|lists)|subscriptions|servicePrincipals|applications/[^/]+/(?:addPassword|addKey)|oAuth2PermissionGrants|identity/conditionalAccess/policies|groups\b)`),

	// ── Google abuse surface ──
	v(classC2APIAbuse, "googleapis.com", `\bwww\.googleapis\.com/(?:drive/v\d+/files|gmail/v\d+/users/[^/]+/messages|calendar/v\d+/calendars/[^/]+/events|youtube/v\d+/(?:videos|playlists))\b`),
	v(classC2APIAbuse, "sheets.googleapis", `\bsheets\.googleapis\.com/v\d+/spreadsheets/[\w-]+/values/|\bslides\.googleapis\.com/v\d+/presentations/[\w-]+`),
	v(classC2APIAbuse, "script.google.com", `\bscript\.google\.com/macros/s/[\w-]+/exec\b`),
	v(classC2APIAbuse, "translate.google", `\btranslate\.google\.com/translate\?[^"\n]{0,120}\bu=https?%3A|\.translate\.goog/\b`),
	v(classC2APIAbuse, "duckduckgo", `\bproxy\.duckduckgo\.com/iu/\?u=`),

	// ── File hosts & cloud storage APIs ──
	v(classC2APIAbuse, "dropbox", `\b(?:content\.dropboxapi\.com|api\.dropboxapi\.com)/\d+/files/(?:upload|download|list_folder|get_shared_link_metadata)\b`),
	v(classC2APIAbuse, "onedrive", `\b(?:api\.onedrive\.com/v\d+|graph\.microsoft\.com/v1\.0/me/drive)/(?:items|root|shares)/|\b1drv\.ms/`),

	// ── Social / media C2 covers ──
	v(classC2Service, "reddit", `\boauth\.reddit\.com/api/v\d+/|\boauth\.reddit\.com/r/[\w-]+/(?:new|hot)\.json|\bwww\.reddit\.com/r/[\w-]+/comments/`),
	v(classC2Service, "twitter", `\bapi\.twitter\.com/(?:1\.1|2)/(?:statuses|tweets|users|direct_messages)/`),
	v(classC2Service, "x.com", `\bapi\.x\.com/(?:1\.1|2)/(?:statuses|tweets|users|direct_messages)/`),
	v(classC2Service, "instagram", `\bgraph\.instagram\.com/v\d+/[\w.-]+/(?:media|messages)`),
	v(classC2Service, "mastodon", `/api/v\d+/(?:statuses|timelines/home|accounts/verify_credentials|streaming)\b[^"\n]{0,80}mastodon|\bmastodon\.social/api/v\d+/`),
	v(classC2Service, "spotify", `\bapi\.spotify\.com/v\d+/(?:me/player|playlists/[\w-]+/tracks|users/[\w-]+/playlists)`),
	v(classC2Service, "soundcloud", `\bapi\.soundcloud\.com/(?:tracks|users|playlists)/\d+/comments\b`),
	v(classC2Service, "youtube", `\bwww\.googleapis\.com/youtube/v\d+/(?:videos|playlistItems|liveChat/messages)\b`),
	v(classC2Service, "strava", `\bwww\.strava\.com/api/v\d+/(?:activities|athletes)/`),
	v(classC2Service, "chess.com", `\bapi\.chess\.com/pub/player/[\w-]+/(?:stats|games/archives)`),
	v(classC2Service, "lichess", `\blichess\.org/api/(?:bot|games|stream)/`),

	// ── Mail / messaging C2 ──
	v(classC2Service, "outlook.office", `\boutlook\.office\.com/api/v\d+/me/MailFolders\b|\boutlook\.office\.com/connectors/webhook\b`),
	v(classC2Service, "mail.google.com", `\bmail\.google\.com/mail/\b`),

	// ── AI / LLM APIs used for C2 (prompt-as-channel) ──
	v(classC2Service, "openai", `\bapi\.openai\.com/v\d+/(?:chat/completions|completions|files|assistants|threads|responses)\b`),
	v(classC2Service, "anthropic", `\bapi\.anthropic\.com/v\d+/(?:messages|complete|batches)\b`),

	// ── Blockchain RPC (LOLC2: smart-contract C2) ──
	// Blockchain RPC endpoints used by smart-contract C2. Two hints cover the
	// common providers so the walker short-circuits cheaply.
	v(classC2Service, "rpc", `\brpc\.ankr\.com/|\b[\w-]+-rpc\.publicnode\.com\b|\bpolygon-rpc\.com\b|\bcloudflare-eth\.com\b|\b[\w.-]+\.infura\.io/v\d+/|\b[\w.-]+\.alchemy\.com/v\d+/|\bapi\.blockcypher\.com/v\d+/(?:btc|eth|ltc|doge)/main/(?:addrs|txs)/`),
	v(classC2Service, "scan.io", `\b[\w.-]*\.(?:etherscan\.io|bscscan\.com|polygonscan\.com|arbiscan\.io|snowtrace\.io)/api\?`),
	v(classC2Service, "bscscan", `\bbscscan\.com/api\?`),

	// ── Webhook sinks beyond those already in script.go (LOTWebhooks) ──
	v(classC2Service, "zulipchat", `\.zulipchat\.com/api/v\d+/messages\b`),
	v(classC2Service, "webex-api", `\bwebexapis\.com/v\d+/messages\b`),
	v(classC2Service, "pagerduty", `\bevents\.pagerduty\.com/v\d+/enqueue\b`),
	v(classC2Service, "flock", `\.flock\.com/hooks/sendMessage/`),
	v(classC2Service, "pushover", `\bapi\.pushover\.net/\d+/messages\.json\b`),
	v(classC2Service, "line.me", `\bnotify-api\.line\.me/api/notify\b`),
	v(classC2Service, "ntfy", `\bntfy\.sh/\w`),
	v(classC2Service, "hc-ping", `\bhc-ping\.com/[0-9a-f-]{8,}\b`),
	v(classC2Service, "make.com", `\bhook\.(?:us|eu|ap|sa)\d*\.make\.com/\w|\bhook\.integromat\.com/\w`),
	v(classC2Service, "trello.com/", `\bapi\.trello\.com/\d+/tokens/[\w-]+/webhooks/\?callbackURL=`),
	v(classC2Service, "n8n", `\.app\.n8n\.cloud/webhook/[\w-]+`),
	v(classC2Service, "sctapi.ftqq", `\bsctapi\.ftqq\.com/[\w]+\.send\b`),
	v(classC2Service, "pushplus", `\bwww\.pushplus\.plus/send\b`),
	v(classC2Service, "typedwebhook", `\btypedwebhook\.tools/\w`),
	v(classC2Service, "webhook-test.com", `\bwebhook-test\.com/\w`),
	v(classC2Service, ".webhook.cool", `\.webhook\.cool/\w`),
	v(classC2Service, "octo.hk", `\bocto\.hk/\w`),
	v(classC2Service, ".emailhook.site", `@emailhook\.site\b|\.dnshook\.site\b`),

	// ── Tunnels not yet in script.go (LOTTunnels) ──
	v(classC2Service, "tailscale", `\b[\w.-]+\.(?:tailscale\.(?:com|io)|ts\.net)\b`),
	v(classC2Service, "qsocket", `\.qsocket\.io\b`),
	v(classC2Service, "shellhub", `\.shellhub\.io\b`),
	v(classC2Service, "tuns.sh", `\.tuns\.sh\b`),
	v(classC2Service, "ssi.sh", `\.ssi\.sh\b`),
	v(classC2Service, "tunnelto.dev", `\.tunnelto\.dev\b`),
	v(classC2Service, "dataplicity", `\.dataplicity\.com\b`),
	v(classC2Service, "openport", `\.openport\.io\b`),
	v(classC2Service, "pitunnel", `\.pitunnel\.com\b`),
	v(classC2Service, "staqlab", `\.staqlab(?:-tunnel)?\.com\b`),
	v(classC2Service, "btunnel", `\.btunnel\.in\b`),
	v(classC2Service, "burrow", `\.burrow\.(?:io|link)\b`),
	v(classC2Service, "cftunnel", `\.cftunnel\.com\b`),
	v(classC2Service, "ngrok", `\bngrok\.(?:app|dev|pro|pizza)\b|\bngrok-free\.app\b|\bngrok-agent\.com\b|\bngrok-cname\.com\b`),
	v(classC2Service, "equinox.io", `\bequinox\.io/\b`),
	v(classC2Service, "expos.es", `\bexpos\.es/|\bexpose\.sh/\w`),
	v(classC2Service, "ipn.dev", `\bipn\.dev\b`),
	v(classC2Service, "iroh.network", `\biroh\.network\b`),
	v(classC2Service, "gsocket", `\bgsocket\.io\b|\bgsocket\.tech\b`),
	v(classC2Service, "tmate", `\btmate\.io\b`),
	v(classC2Service, "ssh-j", `\bssh-j\.com\b`),
	v(classC2Service, "bore.", `\bbore\.(?:digital|pub)\b`),
	v(classC2Service, "localto.net", `\blocalto\.net\b|\blocaltonet\.com\b`),
}

// saasAPIVectors: specific abusable API-path shapes from LOLC2's catalogue
// of C2-over-SaaS projects. These convict more strongly than naming the host
// because the exact path is what an agent uses, not what a browser does.
var saasAPIVectors = []vector{
	// FireBase: realtime DB endpoints the published C2 projects use. A
	// read-only /.json GET is benign; the per-agent/task/results path shape is
	// what the catalogued tooling writes to.
	v(classC2APIAbuse, "firebaseio", `\b[\w-]*\.firebaseio\.com/(?:agents|tasks|results|files|uploads|heartbeat)/[\w./-]*\.json`),

	// Microsoft Teams channel messages / members via Graph: used by Power
	// Automate C2 as the data plane.
	v(classC2APIAbuse, "/teams/", `graph\.microsoft\.com/(?:v1\.0|beta)/teams/[\w-]+/channels/[\w%@-]+/messages`),

	// SharePoint list / drive item write, LOLC2 uses it as a dead-drop.
	v(classC2APIAbuse, "/sites/", `graph\.microsoft\.com/v1\.0/sites/[^/]+/(?:drive/items/[^/]+/content|lists/[\w-]+/items)`),

	// Azure Application Proxy: a specific registration URL shape that only a
	// published C2 agent hits.
	v(classC2APIAbuse, "cloudwebappproxy", `login\.microsoftonline\.com/common/oauth2/authorize\?resource=https%3A%2F%2Fproxy\.cloudwebappproxy\.net%2Fregisterapp`),

	// Dropbox content endpoint used to upload/download blobs.
	v(classC2APIAbuse, "dropboxapi", `content\.dropboxapi\.com/\d+/files/(?:upload|download)\b`),

	// GitHub Contents API PUT -- how an agent writes its exfil blob into a
	// repository (not how a user reads one). Needs method=PUT somewhere in the
	// same 400-byte window, in either order, so the hint is just the host.
	v(classC2APIAbuse, "api.github.com/repos",
		`(?:-X\s+PUT|method\s*=\s*['"]PUT|:\s*['"]PUT)[^\n]{0,400}api\.github\.com/repos/[\w.-]+/[\w.-]+/contents/|api\.github\.com/repos/[\w.-]+/[\w.-]+/contents/[\w./-]+\b[^\n]{0,400}(?:-X\s+PUT|"message"\s*:\s*"[^"\n]+"\s*,\s*"content"\s*:|method\s*=\s*['"]PUT)`),

	// pastebin publish (write via api/api_post.php) -- publishing is agentic;
	// reading /raw is already in the channel class.
	v(classC2APIAbuse, "pastebin.com", `pastebin\.com/api/api_post\.php\b`),

	// Zoom's chat endpoint -- rarely touched outside of custom integrations.
	v(classC2APIAbuse, "api.zoom.us", `api\.zoom\.us/v\d+/(?:chat/users/|accounts/[\w-]+/phone)`),

	// Mastodon statuses POST (publishing is the channel).
	v(classC2APIAbuse, "statuses", `/api/v\d+/statuses\b[^\n]{0,200}(?:-X\s+POST|method\s*=\s*['"]POST|'status'\s*:)`),

	// WhatsApp Cloud API -- Business Platform messages endpoint.
	v(classC2APIAbuse, "graph.facebook.com", `graph\.facebook\.com/v\d+\.\d+/\d+/messages\b`),
}
