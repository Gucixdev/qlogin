/* greeter.h - the qlogin terminal greeter: raw-tty input, PAM, session list, qlogind CreateSession, utmp/wtmp/lastlog, exec.
 * stb style: define QLOGIN_IMPLEMENTATION in exactly one file (src/qlogin.c). Needs libpam. Needs qdbus.h included first with its implementation.
 *
 * TEST MODE: setting PAM_CONFIG=<dir> makes PAM read <dir>/qlogin instead of /etc/pam.d/qlogin. It ALSO switches off everything that needs
 * root or touches the system: no setuid/initgroups, no tty chown, and qlogind is only contacted when DBUS_SYSTEM_BUS_ADDRESS is set
 * explicitly (so a test can never create a session on the real logind). A real (non-test) run refuses to start unless it is root.
 * Other test-only env: QLOGIN_VAR (prefix for var/run/utmp, var/log/wtmp, var/log/lastlog), QLOGIN_SESSDIRS (colon list replacing the
 * system session dirs), QLOGIN_DELAY_UNIT_MS (lockout unit, default 1000), QLOGIN_HOME (replaces the home dir).
 */
#ifndef QLOGIN_GREETER_H
#define QLOGIN_GREETER_H
int qlogin_main(int argc, char **argv);
#endif

#ifdef QLOGIN_IMPLEMENTATION
#ifndef QLOGIN_IMPLEMENTATION_DONE
#define QLOGIN_IMPLEMENTATION_DONE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <grp.h>
#include <lastlog.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <utmpx.h>

#define QL_MAXSESS 64

typedef struct { char name[64], exec[256], type[12]; } ql_sess;

/* ---- secure password buffer: one locked page, wiped after use, never echoed ---- */
static struct { char b[4096]; } QLPW __attribute__((aligned(4096)));
static int ql_locked;
static char ql_user[64];
static int ql_testmode;
static struct termios ql_saved;
static int ql_tty_raw;

static void ql_wipe(void) { explicit_bzero(QLPW.b, sizeof QLPW.b); }
static long ql_us(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000000L + t.tv_nsec / 1000; }

/* lockout: failure n (1-based) waits 2^(n-1) units, capped at 30 units. Pure, tested via the timing in tests/run_qlogin. */
static long ql_lock_ms(int failures, long unit_ms)
{
	long u = failures < 1 ? 0 : (failures > 5 ? 30 : (1L << (failures - 1)));
	return (u > 30 ? 30 : u) * unit_ms;
}

static void ql_raw(int on)
{
	struct termios t;
	if (on) {
		if (!ql_tty_raw) { if (tcgetattr(0, &ql_saved) < 0) return; ql_tty_raw = 1; }
		t = ql_saved;
		t.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
		t.c_iflag &= ~(ICRNL | IXON);
		t.c_cc[VMIN] = 1; t.c_cc[VTIME] = 0;
		tcsetattr(0, TCSAFLUSH, &t);
	} else if (ql_tty_raw) tcsetattr(0, TCSAFLUSH, &ql_saved);
}

enum { QK_EOF = -1, QK_UP = 256, QK_DOWN, QK_ENTER, QK_INT, QK_EOT, QK_BS, QK_KILL, QK_TAB, QK_BTAB, QK_RESIZE, QK_SESS };
static volatile sig_atomic_t ql_winch;
static void ql_on_winch(int sig) { (void)sig; ql_winch = 1; }   /* installed without SA_RESTART: the blocked read() returns and the form redraws */

static int ql_key(void)
{
	unsigned char c;
	for (;;) {
		ssize_t r = read(0, &c, 1);
		if (r == 1) break;
		if (r < 0 && errno == EINTR) { if (ql_winch) { ql_winch = 0; return QK_RESIZE; } continue; }
		return QK_EOF;
	}
	switch (c) {
	case 3: return QK_INT;
	case 4: return QK_EOT;
	case '\t': return QK_TAB;
	case '\r': case '\n': return QK_ENTER;
	case 0x7f: case 8: return QK_BS;
	case 21: return QK_KILL;
	case 19: return QK_SESS;   /* Ctrl-S: ask for the session after login */
	case 27: {
		unsigned char s[2];
		if (read(0, &s[0], 1) != 1) return 27;
		if (s[0] == '[' && read(0, &s[1], 1) == 1) { if (s[1] == 'A') return QK_UP; if (s[1] == 'B') return QK_DOWN; if (s[1] == 'Z') return QK_BTAB; }
		return 27;
	}
	}
	return c;
}

static void ql_say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void ql_say(const char *fmt, ...)
{
	char b[512];
	va_list ap;
	va_start(ap, fmt); vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
	write(1, b, strlen(b));
}

/* ---- the screen: one centred green-on-black panel, two framed fields (log, pwd), Tab moves between them ----
 * Everything is green except a failure, which turns the pwd frame and the one-word message red ("wrong!", "error!"). The password is never
 * drawn at all: the pwd field stays empty and the cursor does not move, so neither the length nor the fact of typing shows. One write() per frame. */
#define QL_G "\033[0;32;40m"
#define QL_R "\033[0;31;40m"
#define QL_PW 32   /* panel width */
#define QL_PH 9    /* panel height */
#define QL_FW 28   /* field frame width */
#define QL_TW 23   /* visible text columns in a field (the last one is the cursor) */

static int ql_rows = 24, ql_cols = 80;
static char ql_fb[8192];
static size_t ql_fn;
static int ql_ask;               /* Ctrl-S in the form: show the session picker after the login */
static const char *ql_err;       /* "wrong!" / "error!" shown in red until the next key */
static int ql_show_time;
static long ql_t0, ql_first = -1;

/* the terminal size: TIOCGWINSZ, and where that says 0 (a serial console, a VM) ask the terminal itself: park the cursor far away and read its position report */
static void ql_size(void)
{
	struct winsize w;
	if (ioctl(1, TIOCGWINSZ, &w) == 0 && w.ws_row > 0 && w.ws_col > 0) { ql_rows = w.ws_row; ql_cols = w.ws_col; return; }
	{
		static const char q[] = "\033[s\033[999;999H\033[6n\033[u";
		char b[32];
		size_t n = 0;
		int r, c;
		struct pollfd pf = { 0, POLLIN, 0 };
		if (write(1, q, sizeof q - 1) < 0) return;
		while (n < sizeof b - 1 && poll(&pf, 1, 300) > 0 && read(0, b + n, 1) == 1) { if (b[n++] == 'R') break; }
		b[n] = 0;
		{ char *e = strrchr(b, 27); if (e && sscanf(e, "\033[%d;%dR", &r, &c) == 2 && r > 0 && c > 0) { ql_rows = r; ql_cols = c; } }
	}
}

static void ql_ap(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void ql_ap(const char *fmt, ...)
{
	va_list ap;
	int n;
	va_start(ap, fmt); n = vsnprintf(ql_fb + ql_fn, sizeof ql_fb - ql_fn, fmt, ap); va_end(ap);
	if (n > 0) ql_fn += (size_t)n < sizeof ql_fb - ql_fn ? (size_t)n : sizeof ql_fb - ql_fn - 1;
}
static void ql_rep(const char *s, int n) { while (n-- > 0) ql_ap("%s", s); }
static void ql_flush(void) { size_t o = 0; while (o < ql_fn) { ssize_t w = write(1, ql_fb + o, ql_fn - o); if (w < 0 && errno == EINTR) continue; if (w <= 0) break; o += (size_t)w; } ql_fn = 0; }

/* a frame with its interior blanked; label (may be NULL) sits in the top edge */
static void ql_box(int y, int x, int w, int h, const char *label)
{
	ql_ap("\033[%d;%dH┌", y, x);
	if (label) { ql_ap("─ %s ", label); ql_rep("─", w - 2 - 3 - (int)strlen(label)); } else ql_rep("─", w - 2);
	ql_ap("┐");
	for (int i = 1; i < h - 1; i++) { ql_ap("\033[%d;%dH│", y + i, x); ql_rep(" ", w - 2); ql_ap("│"); }
	ql_ap("\033[%d;%dH└", y + h - 1, x); ql_rep("─", w - 2); ql_ap("┘");
}

static void ql_begin(int full)
{
	if (full) ql_size();   /* only on a full redraw (start, resize): the serial-console query reads the keyboard line and must not eat typing */
	ql_fn = 0;
	ql_ap("%s\033[?25l", QL_G);
	if (full) ql_ap("\033[2J");
}

static void ql_foot(void)
{
	if (!ql_show_time) return;
	if (ql_first < 0) ql_first = ql_us() - ql_t0;
	ql_ap("\033[%d;1H%s first prompt after %ld us", ql_rows, QL_G, ql_first);
}

/* focus: 0 = log, 1 = pwd. err: NULL or the red word. */
static void ql_draw_form(int focus, const char *err, int full)
{
	int y0, x0, ul = (int)strlen(ql_user), shown = ul > QL_TW ? ul - QL_TW : 0;
	ql_begin(full);
	y0 = (ql_rows - QL_PH) / 2 + 1; if (y0 < 1) y0 = 1;
	x0 = (ql_cols - QL_PW) / 2 + 1; if (x0 < 1) x0 = 1;
	ql_box(y0, x0, QL_PW, QL_PH, NULL);
	ql_box(y0 + 1, x0 + 2, QL_FW, 3, "log");
	ql_ap("\033[%d;%dH%s", y0 + 2, x0 + 4, ql_user + shown);
	if (err) ql_ap("%s", QL_R);
	ql_box(y0 + 4, x0 + 2, QL_FW, 3, "pwd");
	if (err) ql_ap("\033[%d;%dH%s", y0 + 7, x0 + 1 + (QL_PW - 2 - (int)strlen(err)) / 2, err);
	ql_ap("%s", QL_G);
	if (focus == 0) ql_ap("\033[%d;%dH", y0 + 2, x0 + 4 + ul - shown);
	else ql_ap("\033[%d;%dH", y0 + 5, x0 + 4);   /* the cursor never moves in pwd: no stars, no length, no sign of typing */
	ql_ap("\033[?25h");
	ql_foot();
	ql_flush();
}

/* Reads both fields. Returns 1 on Enter in pwd with a user name (ql_user + QLPW.b filled), -1 on Ctrl-D at an empty log / EOF.
 * Ctrl-C clears both fields. Tab / Shift-Tab / Up / Down move between the frames; Enter in log moves to pwd. */
static int ql_form(void)
{
	int focus = ql_user[0] ? 1 : 0, full = 1;
	size_t ul = strlen(ql_user), pn = strlen(QLPW.b);
	ql_ask = 0;
	for (;;) {
		int k;
		ql_draw_form(focus, ql_err, full);
		full = 0;
		k = ql_key();
		if (k == QK_RESIZE) { full = 1; continue; }
		ql_err = NULL;
		if (k == QK_EOF) return -1;
		if (k == QK_INT) { ql_user[0] = 0; ql_wipe(); ul = pn = 0; focus = 0; continue; }
		if (k == QK_EOT) { if (!ul && !pn) return -1; continue; }
		if (k == QK_SESS) { ql_ask = 1; continue; }
		if (k == QK_TAB || k == QK_BTAB || k == QK_UP || k == QK_DOWN) { focus = !focus; continue; }
		if (k == QK_ENTER) {
			if (focus == 0) { if (ul) focus = 1; continue; }
			if (!ul) { focus = 0; continue; }
			return 1;
		}
		if (k == QK_BS) { if (focus == 0 && ul) ql_user[--ul] = 0; else if (focus == 1 && pn) QLPW.b[--pn] = 0; continue; }
		if (k == QK_KILL) { if (focus == 0) { ql_user[0] = 0; ul = 0; } else { ql_wipe(); pn = 0; } continue; }
		if (k < 32 || k > 255) continue;
		if (focus == 0 && ul + 1 < sizeof ql_user) { ql_user[ul++] = (char)k; ql_user[ul] = 0; }
		else if (focus == 1 && pn + 1 < sizeof QLPW.b) { QLPW.b[pn++] = (char)k; QLPW.b[pn] = 0; }
	}
}

/* ---- sessions ---- */
static int ql_scan_dir(ql_sess *out, int n, const char *dir, const char *type)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	if (!d) return n;
	while ((e = readdir(d)) && n < QL_MAXSESS - 1) {
		char path[512], line[512];
		ql_sess s = {0};
		FILE *f;
		int in = 0, hidden = 0;
		size_t l = strlen(e->d_name);
		if (l < 9 || strcmp(e->d_name + l - 8, ".desktop")) continue;
		snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
		if (!(f = fopen(path, "r"))) continue;
		while (fgets(line, sizeof line, f)) {
			line[strcspn(line, "\r\n")] = 0;
			if (line[0] == '[') in = !strcmp(line, "[Desktop Entry]");
			else if (!in) continue;
			else if (!strncmp(line, "Name=", 5) && !s.name[0]) snprintf(s.name, sizeof s.name, "%.63s", line + 5);
			else if (!strncmp(line, "Exec=", 5)) snprintf(s.exec, sizeof s.exec, "%.255s", line + 5);
			else if (!strcmp(line, "Hidden=true") || !strcmp(line, "NoDisplay=true")) hidden = 1;
		}
		fclose(f);
		if (hidden || !s.exec[0]) continue;
		if (!s.name[0]) snprintf(s.name, sizeof s.name, "%.*s", (int)(l - 8), e->d_name);
		/* drop the %f/%u field codes of the desktop entry spec */
		for (char *p = s.exec; *p; p++) if (*p == '%' && p[1]) { memmove(p, p + 2, strlen(p + 2) + 1); p--; }
		snprintf(s.type, sizeof s.type, "%s", type);
		out[n++] = s;
	}
	closedir(d);
	return n;
}

static int ql_sessions(ql_sess *out, const struct passwd *pw)
{
	int n = 0;
	const char *over = getenv("QLOGIN_SESSDIRS");
	if (over && ql_testmode) {
		char *c = strdup(over), *sv = NULL;
		for (char *t = strtok_r(c, ":", &sv); t; t = strtok_r(NULL, ":", &sv)) n = ql_scan_dir(out, n, t, "wayland");
		free(c);
	} else {
		n = ql_scan_dir(out, n, "/usr/share/wayland-sessions", "wayland");
		n = ql_scan_dir(out, n, "/usr/share/xsessions", "x11");
	}
	{
		char dir[400];
		snprintf(dir, sizeof dir, "%s/.config/qlogin", pw->pw_dir);
		/* as root read the user's directory with the user's identity: a symlink there must not leak root-only files */
		if (!ql_testmode && geteuid() == 0 && seteuid(pw->pw_uid) < 0) goto noscan;
		n = ql_scan_dir(out, n, dir, "tty");
		if (!ql_testmode && geteuid() != 0) seteuid(0);
	}
noscan:
	snprintf(out[n].name, sizeof out[n].name, "Shell (%s)", pw->pw_shell);
	out[n].exec[0] = 0; snprintf(out[n].type, sizeof out[n].type, "tty");
	return n + 1;
}

/* The session is not asked for (like SDDM): the remembered one (first line of ~/.config/qlogin/last), else the first graphical one, else the shell.
 * Ctrl-S in the login form (ql_ask) shows the picker once. */
static int ql_pick(ql_sess *s, int n, const struct passwd *pw)
{
	int sel = n - 1, k;
	char last[128] = "", path[400];
	FILE *f;
	snprintf(path, sizeof path, "%s/.config/qlogin/last", pw->pw_dir);
	if (!ql_testmode && geteuid() == 0) seteuid(pw->pw_uid);
	if ((f = fopen(path, "r"))) { if (fgets(last, sizeof last, f)) last[strcspn(last, "\n")] = 0; fclose(f); }
	if (!ql_testmode && geteuid() != 0) seteuid(0);
	for (int i = n - 1; i >= 0; i--) if (strcmp(s[i].type, "tty")) sel = i;   /* first graphical */
	for (int i = 0; i < n; i++) if (last[0] && !strcmp(s[i].name, last)) sel = i;
	if (n == 1 || !ql_ask) return sel;
	ql_ask = 0;
	for (int full = 1;;) {
		int vis = n < ql_rows - 4 ? n : ql_rows - 4, top, y0, x0;
		ql_begin(full); full = 0;
		if (vis > 12) vis = 12;
		if (vis < 1) vis = 1;
		top = sel < vis ? 0 : sel - vis + 1;
		y0 = (ql_rows - (vis + 2)) / 2 + 1; if (y0 < 1) y0 = 1;
		x0 = (ql_cols - QL_PW) / 2 + 1; if (x0 < 1) x0 = 1;
		ql_box(y0, x0, QL_PW, vis + 2, "ses");
		for (int i = 0; i < vis && top + i < n; i++) {
			ql_ap("\033[%d;%dH%s %-*.*s \033[0;32;40m", y0 + 1 + i, x0 + 1, top + i == sel ? "\033[0;30;42m" : "", QL_PW - 4, QL_PW - 4, s[top + i].name);
		}
		ql_ap("\033[?25l");
		ql_foot();
		ql_flush();
		k = ql_key();
		if (k == QK_RESIZE) { full = 1; continue; }
		if (k == QK_INT || k == QK_EOF) return -1;
		if ((k == QK_UP || k == QK_BTAB) && sel > 0) sel--;
		else if ((k == QK_DOWN || k == QK_TAB) && sel < n - 1) sel++;
		else if (k >= '1' && k <= '9' && k - '1' < n) sel = k - '1';
		else if (k == QK_ENTER) return sel;
	}
}

static void ql_remember(const struct passwd *pw, const char *name)
{
	char dir[400], path[420];
	pid_t p = fork();   /* as the user, in a child: never write in a user dir with root's identity */
	if (p) { int st; waitpid(p, &st, 0); return; }
	if (!ql_testmode && (setgid(pw->pw_gid) || setuid(pw->pw_uid))) _exit(1);
	snprintf(dir, sizeof dir, "%s/.config/qlogin", pw->pw_dir);
	snprintf(path, sizeof path, "%s/last", dir);
	{ char cfg[420]; snprintf(cfg, sizeof cfg, "%s/.config", pw->pw_dir); mkdir(cfg, 0700); }
	mkdir(dir, 0700);
	FILE *f = fopen(path, "w");
	if (f) { fprintf(f, "%s\n", name); fclose(f); }
	_exit(0);
}

/* ---- PAM ---- */
static char ql_msgs[256];
static int ql_conv(int n, const struct pam_message **m, struct pam_response **r, void *d)
{
	(void)d;
	struct pam_response *a = calloc(n, sizeof *a);
	if (!a) return PAM_BUF_ERR;
	for (int i = 0; i < n; i++) {
		switch (m[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF: a[i].resp = strdup(QLPW.b); break;   /* libpam wipes and frees it */
		case PAM_PROMPT_ECHO_ON: a[i].resp = strdup(ql_user); break;
		default: snprintf(ql_msgs, sizeof ql_msgs, "%s", m[i]->msg ? m[i]->msg : ""); break;
		}
	}
	*r = a;
	return PAM_SUCCESS;
}

/* ---- utmp / wtmp / lastlog ---- */
static void ql_path(char *o, size_t n, const char *def)
{
	const char *v = ql_testmode ? getenv("QLOGIN_VAR") : NULL;
	if (v) snprintf(o, n, "%s%s", v, def + 4);   /* def starts with /var */
	else snprintf(o, n, "%s", def);
}

static void ql_utmp(int type, pid_t pid, const char *line, const char *user)
{
	struct utmpx u;
	char up[300], wp[300];
	memset(&u, 0, sizeof u);
	u.ut_type = type; u.ut_pid = pid;
	snprintf(u.ut_line, sizeof u.ut_line, "%s", line);
	snprintf(u.ut_id, sizeof u.ut_id, "%s", line + (strlen(line) > 4 ? strlen(line) - 4 : 0));
	snprintf(u.ut_user, sizeof u.ut_user, "%s", user);
	{ struct timespec t; clock_gettime(CLOCK_REALTIME, &t); u.ut_tv.tv_sec = t.tv_sec; u.ut_tv.tv_usec = t.tv_nsec / 1000; }
	ql_path(up, sizeof up, "/var/run/utmp"); ql_path(wp, sizeof wp, "/var/log/wtmp");
	if (utmpxname(up) == 0) { setutxent(); pututxline(&u); endutxent(); }
	updwtmpx(wp, &u);
}

/* returns the previous login time (0 = none) and records the new one */
static time_t ql_lastlog(uid_t uid, const char *line, int update)
{
	char p[300];
	struct lastlog ll;
	time_t prev = 0;
	int fd;
	ql_path(p, sizeof p, "/var/log/lastlog");
	if ((fd = open(p, O_RDWR | O_CLOEXEC)) < 0) return 0;   /* absent file: like login(1), do nothing */
	if (pread(fd, &ll, sizeof ll, (off_t)uid * sizeof ll) == (ssize_t)sizeof ll) prev = ll.ll_time;
	if (update) {
		memset(&ll, 0, sizeof ll);
		ll.ll_time = time(NULL);
		snprintf(ll.ll_line, sizeof ll.ll_line, "%s", line);
		if (pwrite(fd, &ll, sizeof ll, (off_t)uid * sizeof ll) < 0) { /* best effort */ }
	}
	close(fd);
	return prev;
}

/* ---- the session itself ---- */
static const char *ql_ttyname(void)
{
	static char t[64];
	const char *n = ttyname(0);
	snprintf(t, sizeof t, "%s", n ? n : "/dev/tty");
	return t;
}

/* Talks to qlogind. Returns 0 and fills id/rt, with *fifo = the fd whose closing ends the session. Failure is not fatal: login goes on without a logind session. */
static int ql_logind(const struct passwd *pw, pid_t leader, const char *type, const char *desktop, const char *tty, unsigned vt,
                     char *id, size_t idn, char *rt, size_t rtn, int *fifo, char *why, size_t whyn)
{
	const char *addr = getenv("DBUS_SYSTEM_BUS_ADDRESS");
	qd_conn c;
	qd_msg r;
	qd_buf b = {0};
	int rc;
	if (ql_testmode && (!addr || !*addr)) { snprintf(why, whyn, "test mode without DBUS_SYSTEM_BUS_ADDRESS: not talking to any logind"); return -1; }
	if (qd_open(&c, qd_system_address())) { snprintf(why, whyn, "cannot reach the system bus"); return -1; }
	qd_put_u32(&b, pw->pw_uid); qd_put_u32(&b, leader); qd_put_str(&b, "qlogin"); qd_put_str(&b, type); qd_put_str(&b, "user"); qd_put_str(&b, desktop);
	qd_put_str(&b, vt ? "seat0" : ""); qd_put_u32(&b, vt); qd_put_str(&b, tty); qd_put_str(&b, ""); qd_put_u32(&b, 0); qd_put_str(&b, ""); qd_put_str(&b, "");
	{ qd_arr a = qd_arr_begin(&b, 8); qd_arr_end(&b, a); }
	rc = qd_call(&c, &r, "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "CreateSession",
	             "uusssssussbssa(sv)", &b, NULL, 0, 3000);
	free(b.b);
	if (rc) {
		snprintf(why, whyn, rc == 1 ? "logind refused: %s" : "no answer from logind", rc == 1 ? r.err : "");
		if (rc == 1) qd_msg_free(&r);
		qd_close(&c);
		return -1;
	}
	{
		qd_rd rd = { r.body, 0, r.blen, 0 };
		snprintf(id, idn, "%s", qd_r_str(&rd)); qd_r_str(&rd); snprintf(rt, rtn, "%s", qd_r_str(&rd));
		*fifo = r.nfds >= 1 ? r.fds[0] : -1;
		if (r.nfds >= 1) r.fds[0] = -1;
	}
	qd_msg_free(&r);
	qd_close(&c);
	return 0;
}

static void ql_child(const struct passwd *pw, const ql_sess *s, int envfd, char **penv, unsigned vt)
{
	char *env[96], buf[8192], *p = buf;
	int ne = 0, got;
	char cmd[400];
	size_t n = 0;
	setsid();
	/* the new session takes the terminal as its controlling tty (job control, Ctrl-C, hangup when the session leader exits);
	 * the real login is root here and takes it from the greeter's session, the test mode only tries */
	if (ioctl(0, TIOCSCTTY, ql_testmode ? 0 : 1) < 0 && !ql_testmode) fprintf(stderr, "qlogin: no controlling tty (%s)\n", strerror(errno));
	/* session env from the parent: "KEY=VAL\n" lines, ended by EOF (or empty on failure) */
	while ((got = read(envfd, buf + n, sizeof buf - 1 - n)) > 0) n += got;
	buf[n] = 0;
	close(envfd);
	{
		char home[300], user[100], logn[100], shell[300], path[] = "PATH=/usr/local/bin:/usr/bin:/bin", term[100];
		snprintf(home, sizeof home, "HOME=%s", pw->pw_dir); snprintf(user, sizeof user, "USER=%s", pw->pw_name);
		snprintf(logn, sizeof logn, "LOGNAME=%s", pw->pw_name); snprintf(shell, sizeof shell, "SHELL=%s", pw->pw_shell);
		snprintf(term, sizeof term, "TERM=%s", getenv("TERM") ? getenv("TERM") : "linux");
		env[ne++] = strdup(home); env[ne++] = strdup(user); env[ne++] = strdup(logn); env[ne++] = strdup(shell); env[ne++] = strdup(path); env[ne++] = strdup(term);
	}
	while (*p && ne < 80) { char *e = strchr(p, '\n'); if (!e) break; *e = 0; env[ne++] = strdup(p); p = e + 1; }
	{ char t[100]; snprintf(t, sizeof t, "XDG_SESSION_TYPE=%s", s->type); env[ne++] = strdup(t); env[ne++] = strdup("XDG_SESSION_CLASS=user"); }
	if (vt) { char t[100]; snprintf(t, sizeof t, "XDG_VTNR=%u", vt); env[ne++] = strdup(t); env[ne++] = strdup("XDG_SEAT=seat0"); }
	for (int i = 0; penv && penv[i] && ne < 90; i++) env[ne++] = penv[i];
	env[ne] = NULL;
	if (!ql_testmode) {
		{   /* the terminal goes to the user while root can still give it away: group tty + 0620 like login(1), else the user alone */
			struct group *g = getgrnam("tty");
			if (fchown(0, pw->pw_uid, g ? g->gr_gid : pw->pw_gid) == 0) fchmod(0, g ? 0620 : 0600);
		}
		if (initgroups(pw->pw_name, pw->pw_gid) || setgid(pw->pw_gid) || setuid(pw->pw_uid) || setuid(0) == 0) _exit(126);   /* the last: root must not come back */
	}
	if (chdir(pw->pw_dir) < 0 && chdir("/") < 0) _exit(126);
	environ = env;
	signal(SIGINT, SIG_DFL); signal(SIGQUIT, SIG_DFL); signal(SIGPIPE, SIG_DFL); signal(SIGWINCH, SIG_DFL);
	if (!s->exec[0]) {
		const char *base = strrchr(pw->pw_shell, '/');
		char arg0[128];
		snprintf(arg0, sizeof arg0, "-%s", base ? base + 1 : pw->pw_shell);   /* leading dash: a login shell */
		execl(pw->pw_shell, arg0, (char *)NULL);
	} else {
		if (!strcmp(s->type, "x11")) snprintf(cmd, sizeof cmd, "exec startx %s -- vt%u", s->exec, vt ? vt : 1);
		else snprintf(cmd, sizeof cmd, "exec %s", s->exec);
		execl("/bin/sh", "sh", "-lc", cmd, (char *)NULL);
	}
	_exit(127);
}

/* one full login attempt; returns 0 to exit the program, 1 to prompt again */
static int ql_attempt(int *failures, long unit_ms)
{
	pam_handle_t *ph = NULL;
	struct pam_conv conv = { ql_conv, NULL };
	const char *conf = getenv("PAM_CONFIG");
	int r, rc;
	struct passwd *pw;
	ql_msgs[0] = 0;
	if ((rc = ql_form()) < 0) return 0;
	r = conf ? pam_start_confdir("qlogin", ql_user, &conv, conf, &ph) : pam_start("qlogin", ql_user, &conv, &ph);
	if (r != PAM_SUCCESS) { ql_wipe(); ql_err = "error!"; return 1; }
	{ const char *tty = ql_ttyname(); pam_set_item(ph, PAM_TTY, tty); }
	r = pam_authenticate(ph, 0);
	ql_wipe();   /* the password lives exactly as long as pam_authenticate */
	if (r == PAM_SUCCESS) r = pam_acct_mgmt(ph, 0);
	if (r != PAM_SUCCESS) {
		long ms = ql_lock_ms(++*failures, unit_ms);
		ql_err = "wrong!";   /* one word for a wrong user and a wrong password alike: nothing to learn from it */
		ql_draw_form(1, ql_err, 0);
		pam_end(ph, r);
		{ struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L }; while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {} }
		tcflush(0, TCIFLUSH);   /* whatever was typed during the lockout is dropped */
		return 1;
	}
	*failures = 0;
	pw = getpwnam(ql_user);
	if (pw && ql_testmode && getenv("QLOGIN_HOME")) { static struct passwd cp; cp = *pw; cp.pw_dir = getenv("QLOGIN_HOME"); pw = &cp; }   /* tests: never read or write the real home */
	if (!pw) { ql_err = "wrong!"; pam_end(ph, PAM_USER_UNKNOWN); return 1; }
	if (((r = pam_setcred(ph, PAM_ESTABLISH_CRED)) != PAM_SUCCESS && r != PAM_IGNORE) || (r = pam_open_session(ph, 0)) != PAM_SUCCESS) {
		ql_err = "error!"; pam_end(ph, PAM_SYSTEM_ERR); return 1;
	}
	{
		ql_sess ss[QL_MAXSESS];
		int n = ql_sessions(ss, pw), sel = ql_pick(ss, n, pw);
		const char *tty = ql_ttyname();
		unsigned vt = 0;
		int ep[2], fifo = -1, st = 0;
		pid_t kid;
		char id[32] = "", rt[200] = "", why[160] = "", env[600];
		time_t prev;
		if (sel < 0) { pam_close_session(ph, 0); pam_setcred(ph, PAM_DELETE_CRED); pam_end(ph, PAM_SUCCESS); return 1; }
		if (!strncmp(tty, "/dev/tty", 8) && isdigit((unsigned char)tty[8])) vt = (unsigned)atoi(tty + 8);
		ql_remember(pw, ss[sel].name);
		ql_say("\033[2J\033[H");
		prev = ql_lastlog(pw->pw_uid, tty + 5, 0);
		if (prev) { char t[64]; strftime(t, sizeof t, "%a %b %e %H:%M:%S %Y", localtime(&prev)); ql_say("Last login: %s\r\n", t); }
		ql_raw(0);
		if (pipe(ep) < 0) { pam_end(ph, PAM_SYSTEM_ERR); return 0; }
		kid = fork();
		if (kid == 0) { close(ep[1]); ql_child(pw, &ss[sel], ep[0], pam_getenvlist(ph), vt); }
		close(ep[0]);
		env[0] = 0;
		if (ql_logind(pw, kid, ss[sel].type, ss[sel].name, tty, vt, id, sizeof id, rt, sizeof rt, &fifo, why, sizeof why) == 0)
			snprintf(env, sizeof env, "XDG_SESSION_ID=%s\nXDG_RUNTIME_DIR=%s\n", id, rt);
		else fprintf(stderr, "qlogin: running without a logind session (%s)\n", why);
		if (write(ep[1], env, strlen(env)) < 0) { /* child gone */ }
		close(ep[1]);
		signal(SIGINT, SIG_IGN); signal(SIGQUIT, SIG_IGN);
		ql_utmp(USER_PROCESS, kid, tty + 5, pw->pw_name);
		ql_lastlog(pw->pw_uid, tty + 5, 1);
		while (waitpid(kid, &st, 0) < 0 && errno == EINTR) {}
		ql_utmp(DEAD_PROCESS, kid, tty + 5, "");
		if (!ql_testmode && fchown(0, 0, 0) == 0) fchmod(0, 0600);   /* the terminal is root's again before the next login */
		if (fifo >= 0) close(fifo);   /* the logind session ends with this close */
		pam_close_session(ph, 0); pam_setcred(ph, PAM_DELETE_CRED); pam_end(ph, PAM_SUCCESS);
	}
	return 0;
}

int qlogin_main(int argc, char **argv)
{
	long unit = 1000;
	int failures = 0;
	ql_t0 = ql_us();
	if (argc > 1 && !strcmp(argv[1], "-t")) ql_show_time = 1;
	else if (argc > 1) { fputs("usage: qlogin [-t]   (-t: show the microseconds until the first prompt; see qlogin.1)\n", stderr); return 2; }
	ql_testmode = getenv("PAM_CONFIG") != NULL;
	if (!ql_testmode && geteuid() != 0) { fputs("qlogin: must run as root (it is a login program); PAM_CONFIG=<dir> selects the test mode\n", stderr); return 1; }
	if (!isatty(0)) { fputs("qlogin: stdin is not a terminal\n", stderr); return 1; }
	if (ql_testmode && getenv("QLOGIN_DELAY_UNIT_MS")) unit = atol(getenv("QLOGIN_DELAY_UNIT_MS"));
	prctl(PR_SET_DUMPABLE, 0);
	if (mlock(QLPW.b, sizeof QLPW.b) == 0) ql_locked = 1;
	else fprintf(stderr, "qlogin: mlock failed (%s); the password buffer may reach swap\n", strerror(errno));
	signal(SIGPIPE, SIG_IGN);
	{ struct sigaction sa = {0}; sa.sa_handler = ql_on_winch; sigaction(SIGWINCH, &sa, NULL); }
	ql_raw(1);
	while (ql_attempt(&failures, unit)) {}
	ql_raw(0);
	ql_say("\033[0m\033[2J\033[H\033[?25h");
	ql_wipe();
	if (ql_locked) munlock(QLPW.b, sizeof QLPW.b);
	return 0;
}
#endif /* QLOGIN_IMPLEMENTATION */
#endif /* QLOGIN_IMPLEMENTATION_DONE */
