# Attribution

Kaspa Portal is licensed GPL-3.0 (see `LICENSE`).

## KasSigner

Parts of Kaspa Portal's signing core are derived from
[KasSigner](https://github.com/InKasWeRust/KasSigner), an offline signer, seed
manager and stego backup for Kaspa by the KasSigner Project
(kassigner@proton.me), maintained by InKasWeRust, licensed GPL-3.0. They reached
Portal through [KasKold](https://github.com/peavey2787/KasKold), a modified
fork of KasSigner.

The derived code covers the hardware-signer transaction model and transaction
limits, compact KSPT/KSSN and standard PSKT interchange, anti-klepto signing,
covenant and Private Swap signing protocols, BIP32/BIP39/BIP85 derivation and
account-key handling, the password KDF and the power-on self-tests. Those
files were modified for Kaspa Portal and remain under GPL-3.0; source files
that came from KasSigner keep their original copyright notices.
