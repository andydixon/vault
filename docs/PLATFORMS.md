# Platforms

The Go version was built for every target of `go tool dist list` that needs
no cgo: 43 binaries. The Rust release is narrower by decision (Linux,
Windows, macOS, FreeBSD): 16 binaries. This is the target-by-target record:
how each is built, and how far it has actually been verified. "Runtime" means
a binary was executed; "build" means it only compiled and linked.

Tooling used for verification on the development machine (x86-64 Linux):
the pinned Rust 1.99.0, zig 0.16.0 with cargo-zigbuild 0.23.4, qemu-user
10.2.1 (Ubuntu package, unpacked locally, no system changes), glibc cross
sysroots from Ubuntu's `libc6-*-cross` packages, and the Go oracle built for
x86-64. `scripts/smoke.sh` is the runtime check: create a key and vault, store
files across object boundaries, read them back, then have the Go oracle read
what that binary wrote and the binary read what the oracle wrote.

## Released

The release covers Linux, Windows, macOS and FreeBSD (a decision made during
the port: the Go release's more exotic targets are no longer built).

| Go name | Rust target | Linking | Built by | Verified |
| --- | --- | --- | --- | --- |
| linux/amd64 | x86_64-unknown-linux-musl | static | zig | runtime: full test suite (glibc host build) and smoke test of the static binary |
| linux/arm64 | aarch64-unknown-linux-musl | static | zig | runtime: smoke test under qemu-aarch64, cross-checked with the Go oracle |
| linux/386 | i686-unknown-linux-musl | static | zig | runtime: smoke test under qemu-i386, cross-checked |
| linux/armv6 | arm-unknown-linux-musleabihf | static | zig | runtime: smoke test under qemu-arm, cross-checked |
| linux/armv7 | armv7-unknown-linux-musleabihf | static | zig | runtime: smoke test under qemu-arm, cross-checked |
| linux/riscv64 | riscv64gc-unknown-linux-musl | static | zig | runtime: smoke test and crypto unit tests under qemu-riscv64, cross-checked (note 1) |
| linux/loong64 | loongarch64-unknown-linux-musl | static | zig | runtime: smoke test under qemu-loongarch64, cross-checked |
| linux/ppc64le | powerpc64le-unknown-linux-musl | static | zig | runtime: smoke test under qemu-ppc64le, cross-checked |
| linux/s390x | s390x-unknown-linux-gnu | glibc, dynamic | zig | runtime: smoke test under qemu-s390x (big-endian) with an Ubuntu glibc sysroot, cross-checked |
| windows/amd64 | x86_64-pc-windows-gnu | static CRT | zig | build; tests cross-compile cleanly; runtime in CI only (windows-2025 job, not yet run) |
| windows/386 | i686-pc-windows-gnu | static CRT | zig | build only |
| windows/arm64 | aarch64-pc-windows-gnullvm | static CRT | zig | build only |
| darwin/amd64 | x86_64-apple-darwin | system | a Mac, or zig (note 2) | build only from Linux; tested in CI on macos-15-intel |
| darwin/arm64 | aarch64-apple-darwin | system | a Mac, or zig (note 2) | build only from Linux; tested in CI on macos-15 |
| freebsd/amd64 | x86_64-unknown-freebsd | system | cross 0.2.5 (Docker) | build only (no emulator) |
| freebsd/386 | i686-unknown-freebsd | system | cross 0.2.5 (Docker) | build only |

Feature notes: the `unlock` agent works on Linux, macOS and FreeBSD;
Windows asks for the passphrase every time. Full agent hardening
(`PR_SET_DUMPABLE`) is Linux-only; elsewhere the agent locks its memory and
disables core dumps. See `SECURITY.md`.

1. zig's bundled musl `getrandom()` never reaches the kernel on riscv64 (the
   process spins). `build.sh` and `packaging/package.sh` build that target
   with `--cfg getrandom_backend="linux_raw"`, which makes the `getrandom`
   crate issue the system call itself; with that flag the binary passes.
2. Without Apple's SDK there is no Security framework to link, so `build.sh`
   on Linux cross-builds macOS with `--no-default-features`: those binaries
   verify TLS for `add URL` and `mirror` against the bundled Mozilla roots
   instead of the macOS keychain (so a corporate CA added to the keychain is
   not trusted). Built on a Mac, or through Homebrew
   (`brew install andydixon/tap/vault`), they use the keychain.

## No longer released

| Go name | Why |
| --- | --- |
| android/arm64 | was a copy of the static Linux arm64 binary; that binary still runs in Termux, but `add URL`/`mirror` need `/etc/resolv.conf` |
| linux/ppc64 (big-endian) | zig links it for the ELFv2 loader that BE distributions lack; built with `cross` instead, even a hello-world crashes at start-up under qemu-ppc64, so it cannot be verified |
| linux/mips, mipsle, mips64, mips64le | Rust tier 3 (no stable std) since 1.72 |
| netbsd/amd64 | builds only with a newer sysroot than cross 0.2.5 provides (std needs `libexecinfo`); netbsd/386, arm, arm64 are tier 3 |
| openbsd/* | Rust tier 3; OpenBSD packages Rust itself, so a native build there would work |
| freebsd/arm, arm64, riscv64 | Rust tier 3 |
| dragonfly/amd64, aix/ppc64 | Rust tier 3 |
| illumos/amd64, solaris/amd64 | outside the chosen matrix (illumos builds with cross; Solaris has no cross 0.2.5 image) |
| wasip1/wasm | outside the chosen matrix (it builds; no agent, no prompts) |
| js/wasm | no filesystem in the browser target |
| plan9/* | no Rust target |

Asking `build.sh` for any of these reports it and fails.
