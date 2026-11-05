# License FAQ

Plain-language answers to how the Business Source License 1.1 applies to
Sandswap. The license text itself — the `LICENSE` file at the repository
root — is authoritative; this FAQ only explains it. See also MariaDB's
official [adopting-BSL FAQ](https://mariadb.com/bsl-faq-adopting/) for the
general model.

## Q1. Which license applies to which parts?

- **All Sandswap-original code** (gateway, sandlot, boxout, warden, dns,
  sandctl, common, build/deploy/e2e tooling, docs): **BSL 1.1**, Change
  Date **November 30, 2028**, Change License **Apache-2.0**.
- **`network/vsockguard/`** (the vsockguard BPF LSM guard and its loader
  `vsockguardctl`): **GPL-2.0-only OR BUSL-1.1** — dual-licensed. The
  Linux kernel exposes the BPF helpers the guard needs (e.g.
  `bpf_probe_read_kernel`) only to programs carrying a GPL-compatible
  `license` ELF declaration, so the object loaded into the kernel is
  GPL-2.0-only; the BSL branch keeps the component aligned with the rest
  of the repository. Text: `network/vsockguard/LICENSE-GPL-2.0`.
- **`vmm/`** (the `sandvmm` KVM monitor — a purpose-built VMM, not a plain
  Cloud Hypervisor fork: a trimmed Cloud Hypervisor v28.0 base plus the
  vendored virtio-fs virtiofsd, sandbox features ported from the
  CubeSandbox fork, and Sandswap-original code; provenance in
  `vmm/README.md`): **Apache-2.0 OR BSD-3-Clause** — not BSL; free for
  anyone under its own terms.
- The **busybox** binary shipped inside the guest initramfs:
  **GPL-2.0-or-later** (applies to that binary).
- The `LICENSE` and `NOTICE` files at the repository root are authoritative;
  `NOTICE` lists every third-party component.

## Q2. What happens on the Change Date?

Conversion is built into the license text and is automatic — no relicensing
action by anyone, ever. Every version released before the Change Date
becomes Apache-2.0 on November 30, 2028. Versions first released after the
Change Date are Apache-2.0 from the start.

## Q3. Who can use Sandswap for free, and who needs a commercial license?

- Any entity **below** the revenue threshold: any use is free, **including
  production use**.
- A **Revenue Threshold Entity** — an entity, together with the entities it
  Controls or is Under Common Control with, whose annual revenue was at
  least **US$1,000,000,000 in any of calendar years 2026, 2027, or 2028** —
  may use Sandswap free of charge for **internal non-production** purposes
  (development, testing, QA, staging, evaluation). Two things require a
  separate license from the Licensor:
  1. use of the Licensed Work in a **Production Environment**;
  2. **using or distributing** the Licensed Work, alone or incorporated
     into another product or service, in connection with offering that
     product or service to third parties.
- **Procurement**: when a product or service embedding Sandswap is supplied
  to a customer, the restrictions fall on the **supplier** that incorporates
  or distributes it. The customer receiving and using that product as
  supplied is not restricted by reason of that alone.
- **Below-threshold supplier → threshold-entity buyer**: when a supplier
  that is *not* a Revenue Threshold Entity sells a product or service
  embedding Sandswap to a Revenue Threshold Entity, the buyer needs **no
  license** for receiving and using that product **as supplied** (clause
  (d) of the Additional Use Grant). The exemption covers use as supplied
  only: the buyer needs its own license if it instead modifies the embedded
  Sandswap code, extracts the component for standalone deployment in its
  production environment, or redistributes the product to third parties.

"Control", "Under Common Control", and "Production Environment" are defined
in the Additional Use Grant section of the `LICENSE` file.

## Q4. Does using only part of the code still count?

Yes. The license covers the Licensed Work and any copy, modified version, or
derivative of **any portion** of it — there is no per-module or size
threshold. Extracting even a single component into a production environment
triggers the same restrictions for a Revenue Threshold Entity.

Boundary: **using a running Sandswap over its API** (HTTP/MCP clients, agent
SDKs, your own integration code) involves no copy of the Licensed Work at
all and is free for everyone at any scale. The license attaches to code
copies and derivatives, not to network callers.

## Q5. Can I fork Sandswap or build a product on it?

Yes — the BSL grants everyone the right to copy, modify, create derivative
works, and redistribute. The rules:

- Keep the `LICENSE` text and all copyright/license notices intact.
- Modified or derived Sandswap code remains under **BSL 1.1 with the same
  parameters** (same Change Date, same Additional Use Grant) until the
  Change Date. You cannot relicense derived Sandswap code under another
  license before then.
- Your own, genuinely new code carries your copyright, but a derivative
  work of BSL code distributed as a whole stays under BSL.
- After the Change Date the code is Apache-2.0 and these restrictions
  disappear.
- **Users of your fork are bound by the same terms** — forking does not
  exempt a Revenue Threshold Entity from the Additional Use Grant.
- The license grants no trademark rights: do not use the Sandswap name or
  logo for your fork.

## Q6. Is there any warranty or support?

No. The Licensed Work is provided **"AS IS"** and the Licensor disclaims
all warranties and conditions (merchantability, fitness for a particular
purpose, non-infringement, title). No support, maintenance, bug-fix, or
operational obligations are attached to the BSL grant. Support levels, SLAs,
and liability terms are available only through a commercial license
agreement.

## Q7. How do I get a commercial license or an exemption?

Contact the Licensor (the repository owner, Chaoyi Huang) at
**joehuang.sweden@gmail.com**. A BSL production grant is given in
exchange for a **one-time donation** — no recurring fee; the amount
depends only on the company's revenue and is agreed in the license
contract. The license places no conditions on the licensee's use,
scale, or timeline.

You do not need to wait for the contract to be signed before starting
commercial use: negotiations may run while the use is already underway,
and once the contract is signed the license covers that prior use. If the
contract is ultimately not signed, any commercial use that took place in
the meantime remains payable.

The BSL license text itself cannot be modified — all commercial terms live
in that separate contract.

## Q8. How do contributions work?

Contributions are accepted under the project's `CLA.md` (enforced by a
GitHub CLA bot on a contributor's first pull request) and become part of the
Licensed Work under the project license. Contributors keep copyright in
their contributions and may add attribution in file headers and change logs.
