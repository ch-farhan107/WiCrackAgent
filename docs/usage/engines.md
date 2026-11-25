# Cracking engines

## Selection logic

`wicrack` inspects the machine once per run:

1. `--engine` flag forces a backend, otherwise:
2. hashcat available **and** reports > 0 OpenCL/CUDA *GPU* devices → hashcat
3. else John the Ripper available → john (`wpapsk`, CPU SIMD)
4. else hashcat on CPU (works, but slow for WPA)
5. else: clear error with install instructions.

## hashcat backend

- mode 22000 (PMKID + EAPOL), `-O` optimized kernels, workload from settings
- isolated potfile: `data/potfile` (no host potfile pollution)
- live status parsing (`Speed.#`, `Progress`) → dashboard
- optional [hashcat brain](https://hashcat.net/wiki/doku.php?id=brain) client
  (auto-starts the server) to deduplicate candidates across workers
- distributed splitting: `--worker-id/--worker-total` splits rules and
  wordlists (`--skip/--limit`) across machines

## John backend

- hash files converted with `wpapcap2john` (`wpapsk` format)
- `--rules=Best64` maps the best64 rule file to JtR's built-in section
- mask mode uses JtR syntax (`--mask`, `--1=` custom charset) — verified
  against JtR docs, *not* copied from hashcat
- combinator/hybrid kinds are skipped with a notice (JtR limitation);
  the CPU pipeline still covers straight/mask/stdin stages

## Adding a backend

Implement `wicrack.engines.base.Engine` (four methods), return it from the
selector, and every stage works automatically — that is the point of
`AttackSpec` being declarative.
