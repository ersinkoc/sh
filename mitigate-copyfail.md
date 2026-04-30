# mitigate-copyfail

One-shot mitigation script for **CVE-2026-31431 ("Copy Fail")** — the Linux kernel local privilege escalation in `algif_aead` disclosed on April 29, 2026.

The script disables the vulnerable kernel module persistently (and at runtime), updates `initramfs` to prevent auto-load on next boot, and verifies the result. It does **not** install a kernel patch — it buys you safe time until your distro ships a patched kernel.

---

## Quick start

Run on every affected host (servers, K8s nodes, CI runners, sandboxes):

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/sh/main/mitigate-copyfail.sh | sudo bash
```

That single line: downloads the script, runs it as root, applies the mitigation, prints a verification report.

To **only check status** (no changes, no root required for the read-only path):

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/sh/main/mitigate-copyfail.sh | sudo bash -s -- --check
```

To **revert** after you've installed a patched kernel and rebooted:

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/sh/main/mitigate-copyfail.sh | sudo bash -s -- --revert
```

> **Note**: When piping via `curl | bash`, pass arguments after `bash -s --`. The `-s` flag tells bash to read the script from stdin; `--` ends bash's own option parsing so the rest goes to the script.

---

## Inspect before you run

If you don't want to pipe a remote script straight into root (fair), download first, read it, then execute:

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/sh/main/mitigate-copyfail.sh -o mitigate-copyfail.sh
less mitigate-copyfail.sh                  # review the ~200 lines
chmod +x mitigate-copyfail.sh
sudo ./mitigate-copyfail.sh
```

`wget` works too:

```bash
wget -qO- https://raw.githubusercontent.com/ersinkoc/sh/main/mitigate-copyfail.sh | sudo bash
```

Or via `git`:

```bash
git clone https://github.com/ersinkoc/sh.git
cd sh
sudo ./mitigate-copyfail.sh
```

---

## What the script does

1. **System info** — reports kernel version, distro, hostname.
2. **Vulnerability state** — checks if `algif_aead` is currently loaded and whether the persistent blacklist is already in place.
3. **AF_ALG usage detection** — uses `lsof` to list any processes currently holding AF_ALG sockets, so you know what falls back to non-accelerated crypto when the module is unloaded. Typical legitimate users: `cryptsetup`, `systemd-cryptsetup`, `kcapi-*`. Most workloads don't use AF_ALG at all.
4. **Persistent blacklist** — writes `/etc/modprobe.d/disable-algif-aead.conf` so the module can't be auto-loaded.
5. **Live unload** — runs `rmmod algif_aead` to close the hole immediately (no reboot needed if the module isn't pinned).
6. **initramfs update** — runs `update-initramfs -u` (Debian/Ubuntu) or `dracut -f` (RHEL/SUSE family) so the early-boot stage also excludes the module.
7. **Verification** — confirms the module is gone and the blacklist exists; exits non-zero if anything is off.
8. **Next steps** — prints distro-specific commands to install the patched kernel.

---

## Modes

| Command | What it does | Root required |
|---------|--------------|---------------|
| `(no args)` | Apply the mitigation | yes |
| `--check` | Report current state, exit `0` if mitigated, `2` if vulnerable | no |
| `--revert` | Remove the blacklist (only safe after kernel patch + reboot) | yes |
| `--help` | Print usage | no |

Exit codes: `0` ok, `1` missing root, `2` vulnerable / bad arg, `3` verification failed.

---

## Compatibility

Tested logic on:

- Ubuntu 20.04 / 22.04 / 24.04
- Debian 11 / 12
- RHEL 8 / 9 / 10, Rocky Linux, AlmaLinux
- Amazon Linux 2 / 2023
- openSUSE Leap, SLES 15 / 16
- Fedora 39+

Not affected (no action needed): Ubuntu 26.04 (Resolute) and any kernel ≥ 7.0-rc7, ≥ 6.19.12, or ≥ 6.18.22.

---

## What does *not* break

The mitigation only disables `algif_aead`, the kernel's userspace AEAD socket interface. The following continue to work normally:

- **dm-crypt / LUKS** disk encryption
- **kTLS** (kernel TLS offload)
- **IPsec / XFRM** VPN tunnels
- **OpenSSL, GnuTLS, NSS** — they use their own crypto, not AF_ALG
- **SSH** (OpenSSH does its own crypto)
- **Wireguard, OpenVPN**

What *might* break: applications explicitly configured to use the OpenSSL `afalg` engine, or apps that bind directly to AF_ALG `aead`/`skcipher`/`hash` sockets. Run `lsof | grep AF_ALG` on each host to confirm before applying.

---

## Bulk deployment

### Ansible

```yaml
- name: Mitigate CVE-2026-31431
  hosts: linux_servers
  become: true
  tasks:
    - name: Persistent blacklist
      copy:
        dest: /etc/modprobe.d/disable-algif-aead.conf
        content: "install algif_aead /bin/false\n"
        mode: '0644'
    - name: Unload module if loaded
      modprobe:
        name: algif_aead
        state: absent
      ignore_errors: true
    - name: Update initramfs (Debian/Ubuntu)
      command: update-initramfs -u
      when: ansible_os_family == "Debian"
    - name: Update initramfs (RHEL/SUSE)
      command: dracut -f
      when: ansible_os_family in ["RedHat", "Suse"]
```

### Kubernetes DaemonSet

For per-node mitigation across an entire cluster, see the [OVHcloud writeup](https://blog.ovhcloud.com/copy-fail-cve-2026-31431-how-to-rapidly-protect-ovhcloud-mks-clusters-from-the-linux-kernel-zero-day/) — the same DaemonSet pattern works on any K8s distribution.

---

## After the kernel patch

This script is a workaround. The real fix is upstream commit [`a664bf3d603d`](https://git.kernel.org/linus/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5) (mainline) and its stable backports `fafe0fa2995a` (6.18.22) and `ce42ee423e58` (6.19.12). Once your distro ships a kernel with the revert:

```bash
# Ubuntu / Debian
sudo apt update && sudo apt full-upgrade && sudo reboot

# RHEL / Rocky / Alma / Amazon Linux
sudo dnf update kernel && sudo reboot

# SUSE
sudo zypper update kernel-default && sudo reboot
```

After reboot, verify `uname -r` shows the patched version, then optionally run `--revert` to remove the blacklist. On multi-tenant hosts (K8s nodes, CI runners, untrusted-tenant SaaS) it's reasonable to leave the blacklist in place permanently — almost nothing legitimate needs `algif_aead`, and keeping it disabled shuts the door on the entire AF_ALG attack surface.

---

## References

- Theori / Xint disclosure: <https://xint.io/blog/copy-fail-linux-distributions>
- Landing page: <https://copy.fail/>
- CERT-EU advisory: <https://cert.europa.eu/publications/security-advisories/2026-005/>
- Ubuntu Security: <https://ubuntu.com/security/CVE-2026-31431>
- Debian tracker: <https://security-tracker.debian.org/tracker/CVE-2026-31431>
- Sysdig analysis (Falco rule): <https://www.sysdig.com/blog/cve-2026-31431-copy-fail-linux-kernel-flaw-lets-local-users-gain-root-in-seconds>
- oss-security thread: <https://www.openwall.com/lists/oss-security/2026/04/29/23>
- Public PoC: <https://github.com/theori-io/copy-fail-CVE-2026-31431>

---

## License

MIT — use it, fork it, ship it.
