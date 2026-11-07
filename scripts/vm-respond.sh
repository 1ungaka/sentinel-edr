#!/usr/bin/env bash
#
# vm-respond.sh — prove cau defend's response on a real kernel, as real root,
# without root on the host.
#
# Boots the running kernel in QEMU with the real cau binary and vmtest/ as PID 1.
# It really stops a shell on a TCP socket, really kills one, really moves a file
# into the vault, and checks that argv text, /etc and PID 1 are left alone. The
# guest owns its whole kernel and has no network, so nothing here touches the host.
#
# Needs: qemu-system-x86_64, a readable /boot/vmlinuz-$(uname -r), cpio, gzip.

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
kernel="${KERNEL:-/boot/vmlinuz-$(uname -r)}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

[ -r "$kernel" ] || { echo "cannot read $kernel" >&2; exit 1; }

cd "$root"
go build -o "$work/cau" .
image="$work/image"
mkdir -p "$image"/{bin,share,proc,sys,dev,tmp,etc,lib64,usr/lib/x86_64-linux-gnu}
CGO_ENABLED=0 go build -ldflags '-s -w' -o "$image/init" ./vmtest
cp "$work/cau" "$image/bin/cau"
for lib in $(ldd "$work/cau" | awk '/=>/{print $3}'); do
	cp -L "$lib" "$image/usr/lib/x86_64-linux-gnu/"
done
cp -L /lib64/ld-linux-x86-64.so.2 "$image/lib64/"
cp -rL rules "$image/share/rules"
cp -rL signatures "$image/share/signatures"

(cd "$image" && find . -print0 | cpio --quiet --null -o -H newc --owner=0:0 | gzip -1) > "$work/initrd.gz"

accel=(-cpu max)
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
	accel=(-enable-kvm -cpu host)
fi

out="$work/serial.log"
status=0
timeout "${VM_TIMEOUT:-300}" qemu-system-x86_64 "${accel[@]}" -m 2048 -smp 2 \
	-kernel "$kernel" -initrd "$work/initrd.gz" \
	-append "console=ttyS0 panic=-1 quiet loglevel=3" \
	-nographic -no-reboot -nic none < /dev/null > "$out" 2>&1 || status=$?

tr -d '\r' < "$out" | sed -n '/VMRESP/p' | cut -c1-120
tr -d '\r' < "$out" | grep -q 'VMRESP RESULT passed=[1-9][0-9]* failed=0 uid=0' || {
	echo "vm-respond: FAILED (qemu exit $status)" >&2
	tr -d '\r' < "$out" | tail -20 >&2
	exit 1
}
echo "vm-respond: PASSED on $(basename "$kernel")"
