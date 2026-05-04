# CVE-2026-yyyyy-LPE

## Demo

Ubuntu 26.04 LTS with Linux kernel 7.0.0-15-generic



## Build and Run

```bash
cc -O2 exp-passwd.c -o exp
./exp && su
```

## Tested Distros and Versions

| Distro            | Version                          |
| ----------------- | -------------------------------- |
| Ubuntu 26.04 LTS* | 7.0.0-15-generic                 |
| Ubuntu 22.04 LTS* | 5.15.0-164-generic               |
| Ubuntu 20.04 LTS* | 6.6.87.2-microsoft-standard-WSL2 |
| Ubuntu 20.04 LTS* | 5.15.0-1064-azure                |
| Kali Linux 2026.1 | 6.18.12+kali-amd64               |
| Fedora Linux 44   | 6.19.0-300.fc44.x86_64           |

\* Ubuntu versions are tested with apparmor disabled, as it may restrict unprivileged user namespaces, which are required for the exploit to work.

## Affected Kernels

Floor: torvalds/linux cac2661c53f35cbe651bef9b07026a5a05ab8ce0 v4.11

Ceiling: (none yet)

Kernel versions between the floor and ceiling are affected. However, the privilege escalation **only works when user namespaces are enabled**, which is restricted by default in some distro versions (eg. Ubuntu with apparmor enabled).

## Credits

- https://lore.kernel.org/all/afLDKSvAvMwGh7Fy@v4bel/
- https://lore.kernel.org/all/20260504073403.38854-1-h3xrabbit@gmail.com/
- https://copy.fail/
