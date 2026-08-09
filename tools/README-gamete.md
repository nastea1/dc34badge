# Light gene tooling

Two ways to mint a DC34 light-gene gamete. Both speak the exchange protocol correctly using k0,
the AES-256-GCM-SIV key the badges themselves use. Neither contains key material.

## gamete-workbench.html

Self contained, no network, no build step. Open it in a browser, including straight off disk.

1. Paste k0 once. It is checked against bunnie's own oracle, `sha256(k0)` starting `dca9ea49` from
   `dc34-vault/src/main.rs:42`, and kept in localStorage. It is never written into the file.
2. Drop, pick or paste a photo of a badge's key QR. The nonce is read out of it. A manual nonce
   field is there for when a photo will not decode.
3. Choose a preset or move the nine gene sliders.
4. Show the resulting QR to the badge camera in GeneScan.

Everything is inlined: AES-256 and POLYVAL are implemented in plain JavaScript because WebCrypto has
no AES-GCM-SIV, and pure JS also avoids secure-context problems on `file://`.

## mint_gamete.py

Command line equivalent. Reads k0 from `~/dc34-badge/.k0.hex` or `$DC34_K0`.

```
mint_gamete.py scan photo.jpg --respond --preset apex --out gamete.png
mint_gamete.py respond <nonce-hex> --preset apex
mint_gamete.py decode '<base45>' --nonce <yours>
```

## Notes that cost time to learn

* Byte 15 of the plaintext is the incoming badge type. If it equals the receiver's own type the
  firmware flags inbreeding and raises the mutation rate, scrambling the genes you chose. Both tools
  default it to `none`, which no badge capable of breeding can match.
* You contribute one haplotype, not a genome. The receiver runs syngamy against its own egg, and
  expression combines the pair per gene. `hue_base` takes the min and `hue_bound` the max, so a wide
  hue span lands in one exchange. `chaser` is summed, so the rare white chaser needs repeat
  exchanges before it shows.
* Each gamete is sealed under one nonce and is good for a single exchange.

## Verification

The browser build and the Python tool were checked against each other and against outside
references: RFC 9285 base45 vectors, the RFC 8452 POLYVAL vector, AES-256 against a known good
implementation over random inputs, and SHA-256 across every input length from 0 to 200. Both
produce byte-identical sealed output for the same nonce and genes.
