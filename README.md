# DirtyFrag Guard

A Linux defense tool that detects Dirty Frag compromise artifacts and applies
mitigation settings.

## Structure

```text
dirtyfrag_guard.c   Single-file C utility
README.md           Build and usage guide
LICENSE             Project license
```

`dirtyfrag_guard.c` has two modes:

- `--check`: read-only inspection. It does not modify the system.
- `--harden`: root-only mitigation. It writes defensive Linux settings, drops
  page cache, and rechecks the result.

## Build

```bash
gcc -O2 -Wall -Wextra -o dirtyfrag_guard dirtyfrag_guard.c
```

## Check

```bash
./dirtyfrag_guard --check
```

The check mode inspects:

- `/usr/bin/su` for the Dirty Frag ESP payload marker.
- `/etc/passwd` for the RxRPC null-password artifact.
- user namespace sysctls.
- `esp4`, `esp6`, and `rxrpc` module/autoload exposure.

Clean output should end with:

```text
summary: alerts=0 warnings=0 failures=0
```

## Harden

```bash
sudo ./dirtyfrag_guard --harden
```

The harden mode applies:

- `/etc/modprobe.d/dirtyfrag.conf`
- `esp4`, `esp6`, and `rxrpc` install/autoload blocks
- `user.max_user_namespaces=0`
- `/etc/sysctl.d/99-dirtyfrag.conf`
- page-cache drop through `/proc/sys/vm/drop_caches`

Use this only on Linux hosts where temporarily disabling unprivileged user
namespaces is acceptable.

## Keep User Namespaces

If the host needs rootless containers, toolbox, distrobox, or similar tools,
you can keep user namespaces enabled:

```bash
sudo ./dirtyfrag_guard --harden --keep-userns
```

This is weaker because the ESP exploit path may still be reachable depending on
the kernel and module state.

## Exit Codes

```text
0  Clean or no fatal error
1  Operation failure
2  Compromise indicator found
```

## Rollback

```bash
sudo rm -f /etc/modprobe.d/dirtyfrag.conf
sudo rm -f /etc/sysctl.d/99-dirtyfrag.conf
sudo sysctl -w user.max_user_namespaces=31610
```

Reboot after rollback if you want the module and sysctl state fully restored.
