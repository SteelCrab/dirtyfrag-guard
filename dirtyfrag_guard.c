#if !defined(__linux__)
#include <stdio.h>

int main(void)
{
	fputs("dirtyfrag_guard: this defense tool inspects Linux kernel and "
	      "page-cache state. Run it on the Linux host or VM you want to "
	      "check.\n", stderr);
	return 1;
}

#else
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#define SU_ENTRY_OFFSET 0x78
#define SU_READ_LEN 192
#define ET_EXEC 2
#define EM_X86_64 62
#define EM_AARCH64 183

struct options {
	const char *su_path;
	const char *passwd_path;
	int harden;
	int drop_cache;
	int disable_userns;
	int keep_userns;
};

struct module_rule {
	const char *module;
	const char *alias;
	const char *why;
};

static int g_alerts;
static int g_warnings;
static int g_failures;

static const uint8_t x86_64_shell_marker[] = {
	0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a,
};

static const uint8_t aarch64_shell_marker[] = {
	0xe0, 0x03, 0x1f, 0xaa, 0x08, 0x12, 0x80, 0xd2,
};

static void report(const char *level, const char *fmt, ...)
{
	va_list ap;

	if (!strcmp(level, "ALERT"))
		g_alerts++;
	else if (!strcmp(level, "WARN"))
		g_warnings++;
	else if (!strcmp(level, "FAIL"))
		g_failures++;

	printf("[%s] ", level);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
}

static void usage(FILE *out, const char *prog)
{
	fprintf(out,
		"Usage: %s [options]\n"
		"\n"
		"Read-only checks run by default. Root-only actions are explicit.\n"
		"\n"
		"Options:\n"
		"  --check              run checks only (default)\n"
		"  --harden             write modprobe blocks for esp4/esp6/rxrpc,\n"
		"                       block autoload aliases, disable userns,\n"
		"                       try to unload those modules, and drop caches\n"
		"  --drop-cache         sync and write 3 to /proc/sys/vm/drop_caches\n"
		"  --disable-userns     set user namespace sysctls to 0\n"
		"  --keep-userns        with --harden, leave user namespace sysctls unchanged\n"
		"  --su PATH            inspect PATH instead of /usr/bin/su\n"
		"  --passwd PATH        inspect PATH instead of /etc/passwd\n"
		"  -h, --help           show this help\n"
		"\n"
		"Exit codes: 0 clean/no fatal errors, 1 operation failure, 2 compromise indicator found.\n",
		prog);
}

static uint16_t get_le16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint64_t get_le64(const uint8_t *p)
{
	uint64_t v = 0;

	for (int i = 7; i >= 0; i--)
		v = (v << 8) | p[i];
	return v;
}

static int buffer_contains(const uint8_t *buf, size_t len,
		const uint8_t *needle, size_t needle_len)
{
	if (needle_len == 0 || needle_len > len)
		return 0;
	for (size_t i = 0; i + needle_len <= len; i++) {
		if (!memcmp(buf + i, needle, needle_len))
			return 1;
	}
	return 0;
}

static int read_text_file(const char *path, char *buf, size_t cap)
{
	int fd;
	ssize_t n;

	if (cap == 0)
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, cap - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = 0;
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == ' ' ||
				buf[n - 1] == '\t')) {
		buf[--n] = 0;
	}
	return 0;
}

static int write_text_file(const char *path, const char *value)
{
	int fd;
	size_t len = strlen(value);
	size_t off = 0;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	while (off < len) {
		ssize_t n = write(fd, value + off, len - off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		if (n == 0) {
			close(fd);
			errno = EIO;
			return -1;
		}
		off += (size_t)n;
	}
	close(fd);
	return 0;
}

static void check_su_payload(const char *path)
{
	int fd;
	struct stat st;
	uint8_t head[SU_READ_LEN];
	ssize_t n;
	int is_elf64_le = 0;
	uint16_t e_type = 0;
	uint16_t e_machine = 0;
	uint64_t e_entry = 0;
	int x86_marker = 0;
	int arm_marker = 0;
	int x86_payload = 0;
	int arm_payload = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		report("WARN", "%s: cannot open for ESP artifact check: %s",
			path, strerror(errno));
		return;
	}
	if (fstat(fd, &st) == 0) {
		if ((st.st_mode & S_ISUID) && st.st_uid == 0) {
			report("INFO", "%s: setuid-root target present (mode %04o, size %lld)",
				path, st.st_mode & 07777, (long long)st.st_size);
		} else {
			report("WARN", "%s: expected setuid-root su target, got mode %04o uid %u",
				path, st.st_mode & 07777, st.st_uid);
		}
	}

	memset(head, 0, sizeof(head));
	n = pread(fd, head, sizeof(head), 0);
	close(fd);
	if (n < 0) {
		report("WARN", "%s: read failed: %s", path, strerror(errno));
		return;
	}
	if (n < SU_ENTRY_OFFSET + (ssize_t)sizeof(x86_64_shell_marker)) {
		report("WARN", "%s: too small to inspect Dirty Frag payload marker", path);
		return;
	}

	is_elf64_le = n >= 0x40 && !memcmp(head, "\177ELF", 4) &&
		head[4] == 2 && head[5] == 1;
	if (is_elf64_le) {
		e_type = get_le16(head + 16);
		e_machine = get_le16(head + 18);
		e_entry = get_le64(head + 24);
	}

	x86_marker = !memcmp(head + SU_ENTRY_OFFSET, x86_64_shell_marker,
			sizeof(x86_64_shell_marker));
	arm_marker = !memcmp(head + SU_ENTRY_OFFSET, aarch64_shell_marker,
			sizeof(aarch64_shell_marker));

	x86_payload = is_elf64_le && e_type == ET_EXEC &&
		e_machine == EM_X86_64 && e_entry == 0x400078 &&
		x86_marker &&
		buffer_contains(head, (size_t)n, (const uint8_t *)"TERM=xterm", 10) &&
		buffer_contains(head, (size_t)n, (const uint8_t *)"/bin/sh", 7);
	arm_payload = is_elf64_le && e_type == ET_EXEC &&
		e_machine == EM_AARCH64 && e_entry == 0x400078 &&
		arm_marker &&
		buffer_contains(head, (size_t)n, (const uint8_t *)"/bin/sh", 7);

	if (x86_payload) {
		report("ALERT", "%s: matches the x86_64 Dirty Frag /usr/bin/su page-cache payload", path);
		return;
	}
	if (arm_payload) {
		report("ALERT", "%s: matches the aarch64 Dirty Frag /usr/bin/su page-cache payload", path);
		return;
	}
	if (x86_marker || arm_marker) {
		report("WARN", "%s: shell marker found at offset 0x%x, but full payload signature did not match",
			path, SU_ENTRY_OFFSET);
		return;
	}

	report("OK", "%s: no Dirty Frag ESP payload marker found", path);
}

static void printable_prefix(const char *src, char *dst, size_t dst_cap)
{
	size_t i;

	if (dst_cap == 0)
		return;
	for (i = 0; i + 1 < dst_cap && src[i] && src[i] != '\n'; i++) {
		unsigned char c = (unsigned char)src[i];
		dst[i] = (c >= 32 && c < 127) ? (char)c : '.';
	}
	dst[i] = 0;
}

static void check_root_passwd_line(const char *path)
{
	FILE *f;
	char line[2048];
	int lineno = 0;
	int found = 0;

	f = fopen(path, "r");
	if (!f) {
		report("WARN", "%s: cannot open for RxRPC artifact check: %s",
			path, strerror(errno));
		return;
	}

	while (fgets(line, sizeof(line), f)) {
		lineno++;
		if (strncmp(line, "root:", 5))
			continue;

		char original[2048];
		char parsed[2048];
		char *fields[5] = {0};
		char display[160];
		char *passwd;
		char *uid;
		char *gid;
		int nf = 0;

		found = 1;
		strncpy(original, line, sizeof(original) - 1);
		original[sizeof(original) - 1] = 0;
		original[strcspn(original, "\n")] = 0;
		strncpy(parsed, original, sizeof(parsed) - 1);
		parsed[sizeof(parsed) - 1] = 0;
		printable_prefix(original, display, sizeof(display));

		fields[nf++] = parsed;
		for (char *p = parsed; *p && nf < 5; p++) {
			if (*p == ':') {
				*p = 0;
				fields[nf++] = p + 1;
			}
		}

		passwd = nf > 1 ? fields[1] : "";
		uid = nf > 2 ? fields[2] : NULL;
		gid = nf > 3 ? fields[3] : NULL;

		if (!strncmp(original, "root::0:0", 9)) {
			report("ALERT", "%s:%d: root entry matches the RxRPC null-password artifact: %s",
				path, lineno, display);
		} else if (passwd[0] == 0) {
			report("ALERT", "%s:%d: root password field is empty: %s",
				path, lineno, display);
		} else if (strcmp(passwd, "x") && passwd[0] != '!' &&
				passwd[0] != '*') {
			report("WARN", "%s:%d: root password field is unusual for shadowed Linux auth: %s",
				path, lineno, display);
		} else {
			report("OK", "%s:%d: root password field is not empty", path, lineno);
		}

		if (!uid || strcmp(uid, "0") || !gid || strcmp(gid, "0")) {
			report("WARN", "%s:%d: root uid/gid fields are not the expected 0:0: %s",
				path, lineno, display);
		}
		break;
	}
	fclose(f);

	if (!found)
		report("WARN", "%s: no root entry found", path);
}

static int proc_module_loaded(const char *module)
{
	FILE *f = fopen("/proc/modules", "r");
	char line[512];
	size_t len = strlen(module);

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, module, len) && line[len] == ' ') {
			fclose(f);
			return 1;
		}
	}
	fclose(f);
	return 0;
}

static int path_exists(const char *path)
{
	return access(path, F_OK) == 0;
}

static int module_list_mentions(const char *file, const char *module)
{
	FILE *f = fopen(file, "r");
	char line[2048];
	char needle[128];
	int found = 0;

	if (!f)
		return 0;
	snprintf(needle, sizeof(needle), "/%s.ko", module);
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, needle)) {
			found = 1;
			break;
		}
	}
	fclose(f);
	return found;
}

static int module_available_in_tree(const char *module, int *builtin)
{
	struct utsname uts;
	char path[512];
	int dep = 0;
	int built = 0;

	*builtin = 0;
	if (uname(&uts) < 0)
		return 0;

	snprintf(path, sizeof(path), "/lib/modules/%s/modules.dep", uts.release);
	dep = module_list_mentions(path, module);
	snprintf(path, sizeof(path), "/lib/modules/%s/modules.builtin", uts.release);
	built = module_list_mentions(path, module);
	*builtin = built;
	return dep || built;
}

static char *skip_ws(char *p)
{
	while (*p == ' ' || *p == '\t')
		p++;
	return p;
}

static char *next_word(char **cursor)
{
	char *p = skip_ws(*cursor);
	char *start;

	if (*p == 0 || *p == '\n' || *p == '#')
		return NULL;
	start = p;
	while (*p && *p != '\n' && *p != '#' && *p != ' ' && *p != '\t')
		p++;
	if (*p) {
		*p = 0;
		p++;
	}
	*cursor = p;
	return start;
}

static int line_has_install_false(char *line, const char *module)
{
	char *cursor = line;
	char *w0 = next_word(&cursor);
	char *w1 = next_word(&cursor);
	char *w2 = next_word(&cursor);

	return w0 && w1 && w2 &&
		!strcmp(w0, "install") &&
		!strcmp(w1, module) &&
		(!strcmp(w2, "/bin/false") || !strcmp(w2, "/bin/true"));
}

static int line_has_alias_off(char *line, const char *alias)
{
	char *cursor = line;
	char *w0 = next_word(&cursor);
	char *w1 = next_word(&cursor);
	char *w2 = next_word(&cursor);

	return w0 && w1 && w2 &&
		!strcmp(w0, "alias") &&
		!strcmp(w1, alias) &&
		!strcmp(w2, "off");
}

static int modprobe_block_present(const char *module, const char *alias,
		char *found_path, size_t found_path_len)
{
	static const char *dirs[] = {
		"/etc/modprobe.d",
		"/run/modprobe.d",
		"/usr/local/lib/modprobe.d",
		"/usr/lib/modprobe.d",
		"/lib/modprobe.d",
		NULL,
	};

	for (int i = 0; dirs[i]; i++) {
		DIR *d = opendir(dirs[i]);
		struct dirent *de;

		if (!d)
			continue;
		while ((de = readdir(d)) != NULL) {
			char path[512];
			FILE *f;
			char line[1024];
			int hit = 0;
			int alias_hit = alias == NULL;

			if (de->d_name[0] == '.')
				continue;
			snprintf(path, sizeof(path), "%s/%s", dirs[i], de->d_name);
			f = fopen(path, "r");
			if (!f)
				continue;
			while (fgets(line, sizeof(line), f)) {
				char line_copy[1024];

				strncpy(line_copy, line, sizeof(line_copy) - 1);
				line_copy[sizeof(line_copy) - 1] = 0;
				if (line_has_install_false(line, module))
					hit = 1;
				if (alias && line_has_alias_off(line_copy, alias))
					alias_hit = 1;
				if (hit && alias_hit)
					break;
			}
			fclose(f);
			if (hit && alias_hit) {
				closedir(d);
				if (found_path && found_path_len > 0) {
					snprintf(found_path, found_path_len, "%s", path);
				}
				return 1;
			}
		}
		closedir(d);
	}
	return 0;
}

static void check_module(const char *module, const char *alias, const char *why)
{
	char sys_path[256];
	char block_path[512] = {0};
	int loaded;
	int sys_present;
	int builtin = 0;
	int available;
	int blocked;

	snprintf(sys_path, sizeof(sys_path), "/sys/module/%s", module);
	loaded = proc_module_loaded(module);
	sys_present = path_exists(sys_path);
	available = module_available_in_tree(module, &builtin);
	blocked = modprobe_block_present(module, alias, block_path, sizeof(block_path));

	if (blocked) {
		report("OK", "%s: modprobe install/autoload block present in %s",
			module, block_path);
	} else if (loaded || sys_present || available) {
		report("WARN", "%s: %s%s%s; no complete install/autoload block found (%s)",
			module,
			loaded ? "loaded" : (sys_present ? "registered" : "available"),
			builtin ? " built-in" : "",
			available && !loaded && !sys_present ? " for autoload" : "",
			why);
	} else {
		report("OK", "%s: not loaded and not found in the current module tree", module);
	}
}

static void check_modules(void)
{
	static const struct module_rule rules[] = {
		{
			"esp4", "xfrm-type-2-50",
			"ESP IPv4 path used by the XFRM variant",
		},
		{
			"esp6", "xfrm-type-10-50",
			"ESP IPv6 path is the sibling XFRM exposure",
		},
		{
			"rxrpc", "net-pf-33",
			"RxRPC path used by the null-password variant",
		},
	};

	for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++)
		check_module(rules[i].module, rules[i].alias, rules[i].why);
}

static void check_sysctls(void)
{
	char value[128];
	long v;
	char *end;

	if (read_text_file("/proc/sys/kernel/unprivileged_userns_clone",
				value, sizeof(value)) == 0) {
		if (!strcmp(value, "0"))
			report("OK", "kernel.unprivileged_userns_clone=0");
		else
			report("WARN", "kernel.unprivileged_userns_clone=%s; unprivileged users may reach the ESP setup path", value);
	} else {
		report("INFO", "kernel.unprivileged_userns_clone is not available on this kernel");
	}

	if (read_text_file("/proc/sys/user/max_user_namespaces",
				value, sizeof(value)) == 0) {
		errno = 0;
		v = strtol(value, &end, 10);
		if (errno || end == value)
			report("INFO", "user.max_user_namespaces=%s", value);
		else if (v == 0)
			report("OK", "user.max_user_namespaces=0");
		else
			report("WARN", "user.max_user_namespaces=%ld; user namespaces are available", v);
	} else {
		report("INFO", "user.max_user_namespaces is not available on this kernel");
	}
}

static void print_kernel_info(void)
{
	struct utsname uts;

	if (uname(&uts) == 0) {
		report("INFO", "kernel: %s %s %s", uts.sysname, uts.release, uts.machine);
	} else {
		report("WARN", "uname failed: %s", strerror(errno));
	}
}

static int write_modprobe_block(void)
{
	const char *path = "/etc/modprobe.d/dirtyfrag.conf";
	const char body[] =
		"# Installed by dirtyfrag_guard.\n"
		"# Blocks Dirty Frag ESP and RxRPC module autoload paths.\n"
		"blacklist esp4\n"
		"blacklist esp6\n"
		"blacklist rxrpc\n"
		"install esp4 /bin/false\n"
		"install esp6 /bin/false\n"
		"install rxrpc /bin/false\n"
		"alias xfrm-type-2-50 off\n"
		"alias xfrm-type-10-50 off\n"
		"alias net-pf-33 off\n";
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	size_t len = sizeof(body) - 1;
	size_t off = 0;

	if (fd < 0) {
		report("FAIL", "%s: cannot write modprobe block: %s",
			path, strerror(errno));
		return -1;
	}
	while (off < len) {
		ssize_t n = write(fd, body + off, len - off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			report("FAIL", "%s: write failed: %s", path, strerror(errno));
			close(fd);
			return -1;
		}
		if (n == 0) {
			report("FAIL", "%s: short write", path);
			close(fd);
			return -1;
		}
		off += (size_t)n;
	}
	close(fd);
	report("OK", "%s: installed esp4/esp6/rxrpc install blocks", path);
	return 0;
}

static int unload_module(const char *module)
{
	int rc;

#ifdef SYS_delete_module
	rc = (int)syscall(SYS_delete_module, module, O_NONBLOCK);
#else
	errno = ENOSYS;
	rc = -1;
#endif
	if (rc == 0) {
		report("OK", "%s: unloaded", module);
		return 0;
	}
	if (errno == ENOENT) {
		report("INFO", "%s: not loaded", module);
		return 0;
	}
	report("WARN", "%s: unload failed: %s", module, strerror(errno));
	return -1;
}

static int drop_page_cache(void)
{
	sync();
	if (write_text_file("/proc/sys/vm/drop_caches", "3\n") < 0) {
		report("FAIL", "drop_caches failed: %s", strerror(errno));
		return -1;
	}
	report("OK", "page cache dropped via /proc/sys/vm/drop_caches");
	return 0;
}

static int disable_userns(void)
{
	int rc = 0;
	char body[512] = "# Installed by dirtyfrag_guard.\n";

	if (path_exists("/proc/sys/kernel/unprivileged_userns_clone")) {
		if (write_text_file("/proc/sys/kernel/unprivileged_userns_clone",
					"0\n") < 0) {
			report("FAIL", "cannot set kernel.unprivileged_userns_clone=0: %s",
				strerror(errno));
			rc = -1;
		} else {
			report("OK", "kernel.unprivileged_userns_clone set to 0");
		}
		strncat(body, "kernel.unprivileged_userns_clone = 0\n",
			sizeof(body) - strlen(body) - 1);
	} else {
		report("INFO", "kernel.unprivileged_userns_clone is not present");
	}

	if (path_exists("/proc/sys/user/max_user_namespaces")) {
		if (write_text_file("/proc/sys/user/max_user_namespaces", "0\n") < 0) {
			report("FAIL", "cannot set user.max_user_namespaces=0: %s",
				strerror(errno));
			rc = -1;
		} else {
			report("OK", "user.max_user_namespaces set to 0");
		}
		strncat(body, "user.max_user_namespaces = 0\n",
			sizeof(body) - strlen(body) - 1);
	} else {
		report("INFO", "user.max_user_namespaces is not present");
	}

	if (strcmp(body, "# Installed by dirtyfrag_guard.\n")) {
		const char *path = "/etc/sysctl.d/99-dirtyfrag.conf";
		int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);

		if (fd < 0) {
			report("WARN", "%s: cannot write persistent sysctl config: %s",
				path, strerror(errno));
		} else {
			size_t len = strlen(body);
			ssize_t n = write(fd, body, len);

			close(fd);
			if (n == (ssize_t)len)
				report("OK", "%s: installed persistent userns limits", path);
			else
				report("WARN", "%s: short write", path);
		}
	}
	return rc;
}

static int apply_hardening(const struct options *opt)
{
	const char *mods[] = { "esp4", "esp6", "rxrpc", NULL };
	int rc = 0;

	if (geteuid() != 0) {
		report("FAIL", "--harden/--drop-cache/--disable-userns require root");
		return -1;
	}

	if (opt->harden) {
		if (write_modprobe_block() < 0)
			rc = -1;
		for (int i = 0; mods[i]; i++)
			if (unload_module(mods[i]) < 0)
				rc = -1;
		if (drop_page_cache() < 0)
			rc = -1;
		if (!opt->keep_userns)
			if (disable_userns() < 0)
				rc = -1;
	}
	if (opt->drop_cache && !opt->harden)
		if (drop_page_cache() < 0)
			rc = -1;
	if (opt->disable_userns && (!opt->harden || opt->keep_userns))
		if (disable_userns() < 0)
			rc = -1;
	return rc;
}

static int parse_args(int argc, char **argv, struct options *opt)
{
	memset(opt, 0, sizeof(*opt));
	opt->su_path = "/usr/bin/su";
	opt->passwd_path = "/etc/passwd";

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--check")) {
			continue;
		} else if (!strcmp(argv[i], "--harden")) {
			opt->harden = 1;
		} else if (!strcmp(argv[i], "--drop-cache")) {
			opt->drop_cache = 1;
		} else if (!strcmp(argv[i], "--disable-userns")) {
			opt->disable_userns = 1;
		} else if (!strcmp(argv[i], "--keep-userns")) {
			opt->keep_userns = 1;
		} else if (!strcmp(argv[i], "--su")) {
			if (++i >= argc)
				return -1;
			opt->su_path = argv[i];
		} else if (!strcmp(argv[i], "--passwd")) {
			if (++i >= argc)
				return -1;
			opt->passwd_path = argv[i];
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(stdout, argv[0]);
			exit(0);
		} else {
			fprintf(stderr, "unknown option: %s\n", argv[i]);
			return -1;
		}
	}
	return 0;
}

static void run_checks(const struct options *opt)
{
	print_kernel_info();
	check_su_payload(opt->su_path);
	check_root_passwd_line(opt->passwd_path);
	check_sysctls();
	check_modules();
}

int main(int argc, char **argv)
{
	struct options opt;
	int do_actions;

	if (parse_args(argc, argv, &opt) < 0) {
		usage(stderr, argv[0]);
		return 1;
	}
	do_actions = opt.harden || opt.drop_cache || opt.disable_userns;

	puts("dirtyfrag_guard: checking Dirty Frag compromise indicators and mitigations");
	run_checks(&opt);

	if (do_actions) {
		int pre_warnings = g_warnings;
		int pre_failures = g_failures;
		int action_warnings;
		int action_failures;

		if (apply_hardening(&opt) < 0) {
			printf("summary: alerts=%d warnings=%d failures=%d\n",
				g_alerts, g_warnings, g_failures);
			return g_alerts ? 2 : 1;
		}
		action_warnings = g_warnings - pre_warnings;
		action_failures = g_failures - pre_failures;

		puts("dirtyfrag_guard: post-action recheck");
		g_alerts = 0;
		g_warnings = action_warnings;
		g_failures = action_failures;
		run_checks(&opt);
	}

	printf("summary: alerts=%d warnings=%d failures=%d\n",
		g_alerts, g_warnings, g_failures);

	if (g_alerts)
		return 2;
	if (g_failures)
		return 1;
	return 0;
}
#endif
