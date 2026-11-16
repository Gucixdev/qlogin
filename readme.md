
---

# qlogin / qlogind

Two small C programs (gnu11, no GLib, no libdbus, no systemd libs) sharing one hand-written D-Bus library.

- `qlogind` - an org.freedesktop.login1 service for the subset real consumers use (exact list and per-row test status: `docs/login1-surface.md`).
- `qlogin` - a terminal login greeter (SDDM-like, zero GUI): one centred green-on-black panel with two framed fields, `log` and `pwd` (Tab moves between them), PAM, CreateSession, utmp/wtmp/lastlog, lockout. `qlogin -t` shows the time to the first prompt.

The screen: everything is one green on black; only a failure turns the pwd frame and one word red (`wrong!` for a bad user or password alike, `error!` for a PAM failure). The password is not drawn at all (no stars, the cursor does not move), so neither its length nor the typing shows. Try it in this terminal with `./rundemotui` (fake PAM, password `secret`, nothing real touched) or as the real login in a throw-away VM with `./rundemovm` (user `demo`, password `secret`).

The session is not asked for, like SDDM: the remembered one (`~/.config/qlogin/last`), else the first graphical one, else the shell. Ctrl-S in the form (before Enter) shows the picker once. On a serial console or in a VM, where the tty reports no size, qlogin asks the terminal for it (cursor position report), so the panel is centred there too.

Design: `docs/design.md`. Man pages: `src/qlogin.1`, `src/qlogind.8`. Run all tests: `./run` (builds first, no arguments). Build: `./build` (BUILD_FORCE=1 forces; `./install -rebuild` starts from a full rebuild; it calls `make`) (bin/qlogin needs libpam, bin/qlogind needs nothing); `make install` (PREFIX, DESTDIR) is explicit and only copies the two binaries and the man pages; `./install` does build + install into `~/.local` (no root, `PREFIX=` changes it).

## Tested (automatically, `./run`, all green)

- `tests/run_qdbus`: marshalling, SCM_RIGHTS fd passing, Hello on a private bus (ASAN/UBSAN).
- `tests/run_login1`: qlogind vs a fake client on a private `dbus-daemon`, 219 checks, plus a cross-check with real sd-bus (`busctl`: introspection, properties, ListSeats). Every row of docs/login1-surface.md except SeatNew/SeatRemoved: sessions, state files, GetSessionByPID/GetUserByPID, all Can* and power actions in dry-run, Lock/Unlock signals, Activate, KillSession (on a forked child), all Manager/Session properties, KillSession/Session.Kill (leader and the whole process tree), Terminate for session/user/seat, KillUser/User.Kill, inhibitors (delay/block), TakeControl/TakeDevice with a real passed fd, Pause/ResumeDevice, controller leaving the bus, session end by closing the fifo.
- `tests/run_qlogin`: qlogin inside a private tmux with a fake PAM stack (pam_exec check, `PAM_CONFIG`): the log/pwd panel, `-t`, wrong passwords (`wrong!`) with growing lockout, nothing drawn for the password, Ctrl-C clears both fields, Ctrl-D, straight into the default session, Ctrl-S picker, the session really running with XDG_SESSION_ID/XDG_RUNTIME_DIR from qlogind, wtmp/lastlog written, session released afterwards.

- `tests/run_vm`: qlogin as the REAL login (non-test path) in a throw-away qemu VM (host kernel, tiny initramfs, `-nic none`, needs /dev/kvm): real pam_unix against a real shadow file, real qlogind on a VM-local dbus, real setuid/initgroups/tty chown. Wrong password and unknown user both say `wrong!`, the right one goes straight into the session (no picker; a small `demo` session that prints the id and the logind session list and ends), the panel is centred on the 100x30 screen although the serial line reports no size, the session runs as uid 1000 with XDG_SESSION_ID from qlogind and shows up in ListSessions, qlogin exits 0 and the VM powers off. Skipped by `./run` when qemu or /dev/kvm is missing.

## Speed (`tests/run_bench`, -O2, this laptop, private session bus used as the fake system bus)

- qlogind: 10000 GetSession calls, one client: 291 ms total, mean 29 us, p50 28 us, p99 64 us, about 34000 calls/s. This is a full round trip through dbus-daemon (client, daemon, qlogind, daemon, client), so most of it is the bus.
- qlogin `-t`: 44-50 us from `main()` to the first prompt (5 runs). Excludes exec and dynamic linking (libpam, libc); the binary uses plain escape sequences, no ncurses, no locale init.

## Trying it for real without installing anything

Examples only, in `contrib/` (PAM stack, D-Bus policy, dinit/runit/systemd units, `NO-POLKIT.txt`); the tests install nothing, and `make install` copies only the binaries and man pages (never the PAM stack or policy).

- Do not do this on a machine that runs systemd-logind or elogind: both want the bus name org.freedesktop.login1.
- Safest: a VM (or a systemd-less container) with a user and a root console. Copy the two binaries, `contrib/pam.d/qlogin` (to /etc/pam.d/), and the D-Bus policy there, start a system bus, then `DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket qlogind &`.
- Then on a spare VT in that VM, as root: `openvt -c 3 -s -- /usr/bin/qlogin` (or `qlogin </dev/tty3 >/dev/tty3`), log in, and check `busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager ListSessions`.
- Without a VM, the test mode (`PAM_CONFIG=<dir> qlogin` against a private `dbus-daemon`, see `tests/run_qlogin`) is the only supported way.

## NOT tested / not implemented (honest list)

- Never run on a real machine, never as the real login service, never attached to the real system bus. This machine runs systemd-logind; nothing here replaces or touches it. `qlogind` refuses to start without `DBUS_SYSTEM_BUS_ADDRESS`. The real (non-test) path of qlogin (setuid/initgroups, tty chown, pam_unix against /etc/shadow) is exercised only inside the VM of `tests/run_vm`, on a serial console, not on a VT; `/etc/pam.d/qlogin` is not shipped (example in contrib/).
- X11 sessions (launched via `startx`) are untested; Wayland sessions are only tested with a fake `Exec`.
- No cgroups (sessions are tracked by a pipe and the /proc parent chain), no DRM master revoke / EVIOCREVOKE, no real VT switching (logged as a dry run), no polkit (authorization is by uid), no ScheduleShutdown, SeatNew/SeatRemoved never emitted (seat0 is static), process-tree kills (KillSession "all", Terminate*, Kill*) follow the leader's descendants in /proc, so a process that double-forks and re-parents to init is missed.
- Power actions are a dry run unless `real_power=1` and a `cmd_*` is configured; the real execution path is untested.
- D-Bus error names are written from memory of sd-bus conventions.
- Compatibility with elogind is limited to docs/login1-surface.md. It is not a drop-in replacement yet.
- Startup speed: `-t` measures from `main()` only, it excludes exec and dynamic linking. The password is copied by libpam during authentication; it wipes its copy, we cannot prove it.
- `lean4/` holds hand-written Lean models of the pure logic (lockout, inhibitors, sessions, devices); see `lean4/README.md` for what each theorem does and does not cover. The C itself is not verified, and `lake build` is not part of `./run`.
