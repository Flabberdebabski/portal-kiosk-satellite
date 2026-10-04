# Local artifacts

Large extracted firmware, kernel trees, APKs and bug reports are excluded from
Git. The current exact-build files were reconstructed under `/tmp` from HTTP
range requests against Meta's public OTA.

Key files:

- `/tmp/terry-boot.img`: exact 64 MiB boot partition, SHA-256
  `d2cf8e36c8e6aa8095b09675e3f60d532976b04c990ea02cc0826a1ccdd35547`
- `/tmp/terry-current-Image`: decompressed installed kernel Image, SHA-256
  `479e1bd73ac63c27bd2baa2887cf31327b0bb9efd5efa7df7e127f1a13eeab8f`
- `/tmp/terry-current-vmlinux`: reconstructed installed-kernel ELF
- `/tmp/terry-current-kallsyms.txt`: 152,665 recovered kallsyms
- `/tmp/terry-manifest.pb`: update_engine payload manifest
- Exact OTA build `5051355900018050`, size `1,216,232,994`, SHA-256
  `5039c12141a913d7801078389490ad1f86e11b328e2b614bf9571102875500ad`
- `current-analysis/kernel.disasm.txt`: full installed-kernel disassembly
- `portal-kernel-source/`: Meta's matching 4.9 source tree
- `portal-*-bugreport.zip`: persistent crash reports containing ramoops output
- `current-tuning/`: pulled Portal audio tuning files

The repository contains the source, exact target constants and written findings needed to continue the work. Copy large artifacts into a durable external archive before `/tmp` is cleaned.
