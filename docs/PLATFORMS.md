# Platforms

The Go version was built for every target of `go tool dist list` that needs
no cgo: 43 binaries. Rust supports fewer operating systems and CPUs with a
prebuilt, stable standard library. This is the target-by-target record:
how each is built, and how far it has actually been verified. "Runtime" means
a binary was executed; "build" means it only compiled and linked.

Tooling used for verification on the development machine (x86-64 Linux):
the pinned Rust 1.99.0, zig 0.16.0 with cargo-zigbuild 0.23.4, qemu-user
10.2.1 (Ubuntu package, unpacked locally, no system changes), glibc cross
sysroots from Ubuntu's `libc6-*-cross` packages, and the Go oracle built for
x86-64. `scripts/smoke.sh` is the runtime check: create a key and vault, store
files across object boundaries, read them back, then have the Go oracle read
what that binary wrote and the binary read what the oracle wrote.

## Supported

| Go name | Rust target | Linking | Built by | Verified |
| --- | --- | --- | --- | --- |
| linux/amd64 | x86_64-unknown-linux-musl | static | zig | runtime: full test suite (glibc host build) and smoke test of the static binary |
| linux/arm64 | aarch64-unknown-linux-musl | static | zig | runtime: smoke test under qemu-aarch64, cross-checked with the Go oracle |
| linux/386 | i686-unknown-linux-musl | static | zig | runtime: smoke test under qemu-i386, cross-checked |
| linux/armv6 | arm-unknown-linux-musleabihf | static | zig | runtime: smoke test under qemu-arm, cross-checked |
| linux/armv7 | armv7-unknown-linux-musleabihf | static | zig | runtime: smoke test under qemu-arm, cross-checked |
| linux/riscv64 | riscv64gc-unknown-linux-musl | static | zig | runtime: smoke test under qemu-riscv64, cross-checked; unit tests under qemu (see note 1) |
| linux/loong64 | loongarch64-unknown-linux-musl | static | zig | runtime: smoke test under qemu-loongarch64, cross-checked |
| linux/ppc64le | powerpc64le-unknown-linux-musl | static | zig | runtime: smoke test under qemu-ppc64le, cross-checked |
| linux/s390x | s390x-unknown-linux-gnu | glibc, dynamic | zig | runtime: smoke test under qemu-s390x (big-endian) with an Ubuntu glibc sysroot, cross-checked |
| linux/ppc64 | powerpc64-unknown-linux-gnu | glibc, dynamic | cross (Docker) | see note 2 |
| android/arm64 | aarch64-unknown-linux-musl | static | zig | build only on Android; it is the linux/arm64 binary (see note 3) |
| windows/amd64 | x86_64-pc-windows-gnu | static CRT | zig | build; tests cross-compile cleanly; runtime in CI only (windows-2025 job, not yet run) |
| windows/386 | i686-pc-windows-gnu | static CRT | zig | build only |
| windows/arm64 | aarch64-pc-windows-gnullvm | static CRT | zig | build only |
| darwin/amd64 | x86_64-apple-darwin | system | a Mac (Xcode) | CI only (macos-15-intel job, not yet run) |
| darwin/arm64 | aarch64-apple-darwin | system | a Mac (Xcode) | CI only (macos-15 job, not yet run) |
| freebsd/amd64 | x86_64-unknown-freebsd | system | cross (Docker) | see note 4 |
| freebsd/386 | i686-unknown-freebsd | system | cross (Docker) | see note 4 |
| netbsd/amd64 | x86_64-unknown-netbsd | system | cross (Docker) | see note 4 |
| illumos/amd64 | x86_64-unknown-illumos | system | cross (Docker) | see note 4 |
| solaris/amd64 | x86_64-pc-solaris | system | cross (Docker) | see note 4 |
| wasip1/wasm | wasm32-wasip1 | n/a | cargo | build only; no agent, no terminal prompts (passphrase from the environment), lock file instead of locks |

Feature notes: the `unlock` agent works on Unix only (Linux, macOS, the BSDs,
illumos, Solaris); Windows asks for the passphrase every time. Full agent
hardening (`PR_SET_DUMPABLE`) is Linux-only; elsewhere the agent locks its
memory and disables core dumps. See `SECURITY.md`.

1. zig's bundled musl `getrandom()` never reaches the kernel on riscv64 (the
   process spins). `build.sh` and `packaging/package.sh` build that target
   with `--cfg getrandom_backend="linux_raw"`, which makes the `getrandom`
   crate issue the system call itself; with that flag the binary passes.
2. zig links big-endian ppc64 for the ELFv2 ABI (`/lib64/ld64.so.2`), but
   big-endian glibc distributions use ELFv1 (`ld64.so.1`), so the zig build
   would not start there. `build.sh` builds it with `cross` (GCC toolchain)
   instead.
3. Go's android/arm64 binary was a static Linux binary used in Termux; this
   is the same. Name resolution for `add URL`/`mirror` reads
   `/etc/resolv.conf`, which Android does not have, so those two commands
   may fail to resolve hosts there; everything else is unaffected.
4. Built with `cross` 0.2.5 images; not executed (no emulator). The
   dependency graph supports these systems (rustix, ring, getrandom).

## Not supported

These Go targets have no Rust target with a prebuilt standard library on the
stable toolchain (Rust tier 3, built only with nightly `-Zbuild-std`, or no
Rust target at all). Building them would need a nightly toolchain and
untested standard libraries, which this project does not ship.

| Go name | Rust status |
| --- | --- |
| aix/ppc64 | tier 3 (powerpc64-ibm-aix) |
| dragonfly/amd64 | tier 3 |
| freebsd/arm, freebsd/arm64, freebsd/riscv64 | tier 3 |
| netbsd/386, netbsd/arm, netbsd/arm64 | tier 3 |
| openbsd/386, amd64, arm, arm64, ppc64, riscv64 | tier 3 (OpenBSD packages Rust itself; building in an OpenBSD VM would work) |
| linux/mips, mipsle, mips64, mips64le | tier 3 since Rust 1.72 |
| plan9/386, amd64, arm | no Rust target |
| js/wasm | wasm32-unknown-unknown has no filesystem or OS access; not meaningful for vault |

Dropping these is a scope change from the Go release (43 binaries) and needs
an explicit decision before a release: either accept the narrower matrix,
or add nightly/native builds for chosen targets (OpenBSD in a VM is the most
practical).
