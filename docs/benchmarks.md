# Benchmarks

Numbers depend heavily on hardware, drivers, and OpenCL runtime. Run:

```bash
wicrack bench
```

and submit your result via PR (one row, include GPU/CPU model and engine).

| Hardware | Engine | WPA speed | Reporter |
|----------|--------|----------:|----------|
| *be the first — PR your `wicrack bench` output!* | | | |

## Reading the numbers

- WPA-PBKDF2 (mode 22000) is **deliberately slow** — 4096 HMAC-SHA1
  iterations per candidate. Consumer GPUs land in the ~50–300 kH/s range;
  a modern laptop CPU in the ~5–30 kH/s range with John's SIMD kernels.
- That is the security property of WPA being assessed: an 8-char random
  password is computationally out of reach, a `Company2023!` is not.
- Use the benchmark with the stage estimators: `auto_ok_hours` decides when
  a heavy stage runs unattended, and that maths is only as good as
  `est_speed`.
