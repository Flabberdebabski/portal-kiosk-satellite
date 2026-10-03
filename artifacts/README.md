# Local artifacts

Large extracted firmware, kernel trees, APKs and bug reports remain under `/tmp/portal-aec-investigation` and are excluded from Git.

Key files:

- `terry-5051355900018050.zip`: exact installed OTA payload
- `current-analysis/kernel.elf`: reconstructed installed kernel ELF
- `current-analysis/kernel.symbols`: recovered kallsyms
- `current-analysis/kernel.disasm.txt`: full installed-kernel disassembly
- `portal-kernel-source/`: Meta's matching 4.9 source tree
- `portal-*-bugreport.zip`: persistent crash reports containing ramoops output
- `current-tuning/`: pulled Portal audio tuning files

The repository contains the source, exact target constants and written findings needed to continue the work. Copy large artifacts into a durable external archive before `/tmp` is cleaned.
