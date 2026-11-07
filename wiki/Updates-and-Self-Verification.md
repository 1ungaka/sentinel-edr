# Updates and Self-Verification

Everything here is anchored in one Ed25519 release key. The private key lives
off the host (a CI secret); the public key is pinned/shipped. Nothing installs
or trusts anything whose signature does not verify.

## Signed releases (how they are made)

The GitHub Actions release job (`.github/workflows/ci.yml`, triggered on a `v*`
tag) runs on GitHub's workers and, with the `CAU_RELEASE_SIGNING_KEY` secret set:

1. Builds the binary and tarball.
2. `cau bundle update` — writes a **signed signature-DB bundle**
   (`hashes.txt` + `manifest.json` + `manifest.json.sig`).
3. `cau bundle checksums` — writes a **signed `SHA256SUMS`** (+ `.sig`) over every
   release artifact.
4. `cau selftest --record --sign-key` — a **signed detection-content baseline**.
5. `cau verify-self` — the job self-verifies the built binary against the signed
   `SHA256SUMS`; **a release that cannot verify itself never ships.**

Set the repo secret `CAU_RELEASE_SIGNING_KEY` (hex Ed25519 seed) and the repo
variable `CAU_RELEASE_PUBLIC_KEY` (matching hex public key). Without the secret,
the release is published unsigned with a warning.

## Verify this binary against its own release (self-reference)

The binary computes its own SHA-256 and checks it against the signed
`SHA256SUMS` — fetched over HTTPS or read from an air-gapped copy:

```sh
cau verify-self --url https://github.com/s-b-repo/cau/releases/download/vX.Y.Z \
                --pubkey release-pubkey.hex --name cau-vX.Y.Z-linux-amd64
# or, offline:
cau verify-self --from /media/usb/cau-release --pubkey release-pubkey.hex --name cau-...
```

The signature is verified **before** the hash is compared, so a MITM of the
download cannot substitute a matching hash. Exit `0` verified, `1` failed.

> ICMP/QUIC "echo-lane" transport for fetching this out-of-band is a future,
> proprietary transport (raw sockets / post-quantum QUIC). The signed-manifest
> path above is the secure, in-engine way today.

## Update the signature database (fail-closed)

```sh
cau update --url https://github.com/s-b-repo/cau/releases/download/vX.Y.Z \
           --pubkey release-pubkey.hex
# or offline:
cau update --from /media/usb/cau-release --pubkey release-pubkey.hex
```

A bad signature, a payload-digest mismatch, an unmet `min_engine_version`, or a
bundle older than the one installed leaves the live database untouched; a success
swaps it atomically, keeps `<db>.bak` for rollback, and records what it installed in
`<db>.manifest`. A signature proves a bundle was released, not that it is current, so
that record is what stops a mirror replaying an old one. To back out a bad release on
purpose, pass `--allow-downgrade`. The first install has nothing to compare against.
With `--from`, files are size-limited and checked before they are read, because the
directory can hold whatever was on the media. The engine never fetches on its own —
update is always an explicit command.
