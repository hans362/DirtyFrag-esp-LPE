# DirtyFrag-esp-LPE

## Demo

Ubuntu 26.04 LTS with Linux kernel 7.0.0-15-generic

https://github.com/user-attachments/assets/0054277b-0b0a-46af-9df5-95cabe780691

## Build and Run

```bash
cc -O2 exp-passwd.c -o exp
./exp && su
```

## Tested Distros and Versions

| Distro            | Version                          |
| ----------------- | -------------------------------- |
| Ubuntu 26.04 LTS* | 7.0.0-15-generic                 |
| Ubuntu 22.04 LTS  | 5.15.0-164-generic               |
| Ubuntu 20.04 LTS  | 6.6.87.2-microsoft-standard-WSL2 |
| Ubuntu 20.04 LTS  | 5.15.0-1064-azure                |
| Kali Linux 2026.1 | 6.18.12+kali-amd64               |
| Fedora Linux 44   | 6.19.0-300.fc44.x86_64           |

\* Ubuntu 26.04 LTS was tested with apparmor disabled, as it may restrict unprivileged user namespaces, which are required for the exploit to work.

## Affected Kernels

Floor: torvalds/linux cac2661c53f35cbe651bef9b07026a5a05ab8ce0 v4.11

Ceiling: torvalds/linux f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4

Kernel versions between the floor and ceiling are affected. However, the privilege escalation **only works when user namespaces are enabled**, which is restricted by default in some distro versions (eg. Ubuntu 26.04 LTS with apparmor enabled).

## Credits

- https://lore.kernel.org/all/afLDKSvAvMwGh7Fy@v4bel/
- https://lore.kernel.org/all/20260504073403.38854-1-h3xrabbit@gmail.com/
- https://copy.fail/

## Disclaimer

This proof-of-concept code is for educational purposes only. It should not be used for any malicious activities. The author is not responsible for any damage caused by the misuse of this code. Always use it in a controlled and legal environment.
