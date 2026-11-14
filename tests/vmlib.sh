# vmlib.sh - sourced by rundemovm and tests/run_vm: builds a tiny initramfs and boots the HOST kernel in qemu with qlogin as the REAL login on the
# serial console: real PAM (pam_unix + /etc/shadow), real qlogind on a VM-local dbus, real setuid/initgroups/tty chown. The host is never touched:
# nothing is installed, no network (-nic none), the repo is not even mounted (binaries and files are copied into the image).
# The VM has one user: demo (uid 1000), password "secret", plus root without a password. When qlogin exits the VM powers off.
set -u
VM_REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VM_USER=demo VM_PASS=secret

vm_need() {
	local b
	for b in qemu-system-x86_64 cpio zstd gcc openssl setsid dbus-daemon bash; do command -v "$b" >/dev/null || { echo "vm: missing host tool '$b' (e.g. ! sudo pacman -S qemu-system-x86 cpio zstd gcc openssl dbus util-linux)" >&2; return 1; }; done
	[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo "vm: /dev/kvm not usable" >&2; return 1; }
	VM_KERNEL=${QT_KERNEL:-}
	for k in "$VM_KERNEL" "/usr/lib/modules/$(uname -r)/vmlinuz" /boot/vmlinuz-linux "/boot/vmlinuz-$(uname -r)"; do [ -n "$k" ] && [ -r "$k" ] && { VM_KERNEL=$k; return 0; }; done
	echo "vm: no readable kernel image" >&2; return 1
}

vm_libs() { # copy every shared lib of an ELF (ldd) to its resolved dir inside the root
	local l p d
	while read -r l; do
		p=$(awk '{ for (i=1;i<=NF;i++) if ($i ~ /^\//) { print $i; exit } }' <<<"$l"); [ -n "$p" ] && [ -e "$p" ] || continue
		d=$(readlink -f "$(dirname "$p")"); [ -e "$VM_ROOT$d/$(basename "$p")" ] && continue
		mkdir -p "$VM_ROOT$d"; cp -L "$p" "$VM_ROOT$d/$(basename "$p")"
	done < <(ldd "$1" 2>/dev/null)
}
vm_bin() { local p; p=$(type -P "$1") || return 0; p=$(readlink -f "$p"); cp -L "$p" "$VM_ROOT/usr/bin/$(basename "$1")"; vm_libs "$p"; }

# vm_build DIR: builds DIR/initramfs.zst (needs gcc + libpam to build qlogin; the binaries are built into DIR, not into the repo)
vm_build() {
	local d=$1 m
	VM_ROOT=$d/root; mkdir -p "$VM_ROOT"/{usr/bin,usr/lib,dev,proc,sys,tmp,etc/pam.d,root,run/dbus,var/run,var/log,home,usr/share/wayland-sessions}
	ln -s usr/bin "$VM_ROOT/bin"; ln -s usr/bin "$VM_ROOT/sbin"; ln -s usr/lib "$VM_ROOT/lib"; ln -s usr/lib "$VM_ROOT/lib64"
	nice -n 19 gcc -std=gnu11 -Wall -Wextra -O2 -I"$VM_REPO/src/mods" "$VM_REPO/src/qlogin.c" -lpam -o "$d/qlogin" || return 1
	nice -n 19 gcc -std=gnu11 -Wall -Wextra -O2 -I"$VM_REPO/src/mods" "$VM_REPO/src/qlogind.c" -o "$d/qlogind" || return 1
	for m in "$d/qlogin" "$d/qlogind"; do cp "$m" "$VM_ROOT/usr/bin/"; vm_libs "$m"; done
	for m in bash sh ls cat mkdir mount sleep grep id env chown chmod true setsid dbus-daemon busctl sync date unix_chkpwd; do vm_bin "$m"; done
	# PAM: the real unix module against a real shadow file (nodelay: qlogin has its own lockout)
	printf 'auth required pam_unix.so nodelay\naccount required pam_unix.so\nsession required pam_unix.so\npassword required pam_unix.so\n' > "$VM_ROOT/etc/pam.d/qlogin"
	for m in pam_unix.so; do p=/usr/lib/security/$m; [ -e "$p" ] || { echo "vm: $p missing" >&2; return 1; }; mkdir -p "$VM_ROOT/usr/lib/security"; cp -L "$p" "$VM_ROOT$p"; vm_libs "$p"; done
	for m in /usr/lib/libnss_files.so.2 /etc/nsswitch.conf /etc/protocols; do [ -e "$m" ] && { mkdir -p "$VM_ROOT$(dirname "$m")"; cp -L "$m" "$VM_ROOT$m"; }; done
	printf 'root:x:0:0:root:/root:/bin/bash\n%s:x:1000:1000:%s:/home/%s:/bin/bash\n' "$VM_USER" "$VM_USER" "$VM_USER" > "$VM_ROOT/etc/passwd"
	printf 'root:x:0:\n%s:x:1000:\n' "$VM_USER" > "$VM_ROOT/etc/group"
	printf 'root:!::::::::\n%s:%s:::::::\n' "$VM_USER" "$(openssl passwd -6 "$VM_PASS")" > "$VM_ROOT/etc/shadow"; chmod 600 "$VM_ROOT/etc/shadow"
	printf '/bin/bash\n' > "$VM_ROOT/etc/shells"
	[ -n "${VM_EXTRA:-}" ] && for m in $VM_EXTRA; do cp "$m" "$VM_ROOT/usr/bin/"; vm_libs "$m"; done   # debug: extra host binaries into the image
	# one wayland-session entry that only shows who and where it runs, then ends (a real compositor cannot run in a text VM)
	cat > "$VM_ROOT/usr/bin/demo-session" <<'D'
#!/usr/bin/bash
id
echo "XDG_SESSION_ID=$XDG_SESSION_ID XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR"
busctl --address=unix:path=/run/dbus/system_bus_socket call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager ListSessions
sleep 3
D
	chmod +x "$VM_ROOT/usr/bin/demo-session"
	printf '[Desktop Entry]\nName=demo\nExec=demo-session\n' > "$VM_ROOT/usr/share/wayland-sessions/demo.desktop"
	cat > "$VM_ROOT/etc/bus.conf" <<'C'
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>session</type><listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth>
<policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/><allow user="*"/></policy></busconfig>
C
	cat > "$VM_ROOT/init" <<'I'
#!/usr/bin/bash
# /init of the demo VM: mount, dbus + qlogind, qlogin as the real login on the serial console; powers off when qlogin exits.
export PATH=/usr/bin
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev 2>/dev/null; mount -t tmpfs tmp /tmp
mkdir -p /home/demo /run/systemd/sessions /run/user; chown 1000:1000 /home/demo; : > /var/log/wtmp; : > /var/run/utmp; : > /var/log/lastlog
dbus-daemon --config-file=/etc/bus.conf --nofork --nopidfile > /tmp/dbus.log 2>&1 &
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S /run/dbus/system_bus_socket ] && break; sleep 0.2; done
DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket qlogind > /tmp/qlogind.log 2>&1 &
sleep 0.5
export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket
case " $(cat /proc/cmdline) " in *" qshell=1 "*) setsid -c bash -c 'exec bash' < /dev/ttyS0 > /dev/ttyS0 2>&1;; esac   # debug: QVM_SHELL=1 gives a root shell instead of the login
setsid -c bash -c 'exec qlogin' < /dev/ttyS0 > /dev/ttyS0 2>&1
echo "QVM qlogin exited rc=$?" > /dev/ttyS0
sync; echo 1 > /proc/sys/kernel/sysrq; echo o > /proc/sysrq-trigger; sleep 5
I
	chmod +x "$VM_ROOT/init"
	(cd "$VM_ROOT" && find . | cpio -o -H newc --quiet 2>/dev/null | zstd -q -3 -o "$d/initramfs.zst") || return 1
}

# vm_qemu DIR: the boot command (run it in a terminal: the VM console is the serial line = this terminal). TERM is handed to the guest init.
vm_qemu() {
	echo qemu-system-x86_64 -enable-kvm -cpu host -m 512M -smp 2 -nographic -no-reboot -nic none \
		-kernel "$VM_KERNEL" -initrd "$1/initramfs.zst" -append "'console=ttyS0 rdinit=/init panic=-1 quiet loglevel=0 TERM=${TERM:-linux}${QVM_SHELL:+ qshell=1}'"
}
