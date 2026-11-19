# NOSIH — Formal Assumptions and Complete Proofs (Theorems 1–5)

This technical appendix provides the explicit mathematical assumptions, scope boundaries, and complete derivations for Theorems 1–5 referenced in `paper/nosih_paper.pdf`.

---

## Trusted Computing Base (TCB) & Scope Assumptions
All Plane I security theorems hold under the following explicit TCB assumptions:
- **A1 (Cryptographic Primitives):** HMAC-SHA256 and SHA-256 are EUF-CMA unforgeable and collision-resistant; root signing keys reside inside `StrictSecretProvider` outside LLM prompt/tool context.
- **A2 (Non-Bypassable Proxy & Storage):** Every privileged MCP tool invocation traverses `NOSIHMCPProxyV3`, and SQLite WAL `BEGIN IMMEDIATE` transactions enforce serializable write isolation on the local host filesystem.
- **A3 (Tool-Boundary Scope):** Security theorems govern *privileged tool invocation, argument integrity/confidentiality, monetary budgets, cache partitioning, and DAG execution*. Free-form unprivileged prose generation that invokes no tool or egress sink lies outside the tool-boundary TCB.

---

## Theorem 1 — Tool-Boundary Non-Interference & Capability Unforgeability
**Statement:** Under Assumptions A1–A3, no untrusted external data ($\iota(x) = \texttt{UNTRUSTED}$) can cause a privileged control sink requiring integrity $\iota_{\text{req}} < \texttt{UNTRUSTED}$ to execute, nor can any principal forge or escalate a Macaroon capability beyond its attenuated caveats.

**Proof:**
1. *Canonical Input Normalization:* `jcs_loads` rejects duplicate keys, NaN/Infinity, and lone UTF-16 surrogates prior to parsing, eliminating parser-differential smuggling between validator and server.
2. *Monotone Semiring Propagation:* The provenance semiring $(\mathcal{L}, \oplus, \otimes)$ defines $\iota(a \oplus b) = \iota(a \otimes b) = \max(\iota(a), \iota(b))$ and $\kappa(a \oplus b) = \kappa(a \otimes b) = \kappa(a) \cup \kappa(b)$. By structural induction over any finite multi-hop DAG or expression tree, if any ancestor input carries $\iota = \texttt{UNTRUSTED}$ (rank 6), every derived value carries $\iota = 6 > \iota_{\text{req}}$.
3. *Sink Enforcement & Macaroon Attenuation:* Before dispatch, `POSTWPlusEngine` checks $\iota(\text{arg}) \le \iota_{\text{req}}$ and `SPCCEMacaroonAuthority` recomputes the chained HMAC-SHA256 tag $\sigma_k = \text{HMAC}(\sigma_{k-1}, \text{JCS}(c_k))$ from the root key. Under A1, removing or relaxing any caveat $c_k$ without the root key succeeds only with negligible probability. Hence no untrusted input can satisfy a high-integrity sink or forge a capability. $\square$

---

## Theorem 2 — Linear Monetary Conservation & Atomic Single-Use JTI
**Statement:** Under A2, for any invoice/budget $B_0 \in \mathbb{Q}_{10}$ (exact base-10 `Decimal`) and any concurrent set of $m$ payout requests $\{a_1, \dots, a_m\}$ or $m$ replayed capability tokens sharing a single `jti`, the total committed payout satisfies $\sum_{i \in S_{\text{allow}}} a_i \le B_0$ and at most one request per `jti` executes.

**Proof:**
1. Every spend check and deduction runs inside a single SQLite WAL `BEGIN IMMEDIATE` transaction acquiring an exclusive RESERVED write lock before reading `remaining_inr`.
2. Let $t_1 < t_2 < \dots < t_m$ be the total serialization order induced by SQLite's write lock. At step $t_k$, the invariant $R_k = B_0 - \sum_{j < k, j \in S_{\text{allow}}} a_j \ge 0$ holds inductively: transaction $k$ commits $R_{k+1} = R_k - a_k$ if and only if $a_k \le R_k$ (in exact `Decimal`, eliminating IEEE-754 rounding drift); otherwise it aborts with $R_{k+1} = R_k$. If downstream dispatch fails, `rollback_linear_budget()` restores $+a_k$ atomically.
3. For JTI replay protection, `INSERT INTO used_jtis(jti) VALUES (?)` enforces a `PRIMARY KEY` uniqueness constraint inside the same serialized write lock; hence strictly $\le 1$ concurrent thread succeeds. $\square$

---

## Theorem 3 — Tamper-Evident $O(\log N)$ Merkle Transparency
**Statement:** Under A1 (SHA-256 collision resistance and EUF-CMA STH signing), any modification, insertion, or truncation of a historical audit or CCEC carbon leaf in an $N$-leaf RFC 6962/9162 `MTLog` is detected by inclusion/consistency verification using $\lceil \log_2 N \rceil$ hashes.

**Proof:**
By domain separation (`0x00 || leaf_bytes` for leaves and `0x01 || left || right` for internal nodes), second-preimage attacks confusing internal nodes with leaves are impossible. Changing any leaf alters its leaf hash, which propagates along the unique root-to-leaf path of length $\le \lceil \log_2 N \rceil$ to a distinct root hash $R' \ne R$. Because $R$ is bound to a signed tree head $\text{STH}_N$, forging an accepting proof requires either a SHA-256 collision or an HMAC forgery, both negligible under A1. Consistency proofs between $M < N$ verify that the first $M$ leaves form an immutable prefix of the $N$-leaf tree. $\square$

---

## Theorem 4 — Dynamic Regret of CA-DPD-LinUCB and Finite-Sample Conformal PID Risk
**Assumptions:**
- **B1 (Bounded Context & Parameter Drift):** For all rounds $t \in \{1,\dots,T\}$ and arms $a \in \{1,\dots,K\}$, context $\|x_{t,a}\|_2 \le L$, true reward parameters $\|\theta_{t,a}\|_2 \le S$, and total non-stationary variation satisfies $\sum_{t=1}^{T-1} \|\theta_{t+1,a} - \theta_{t,a}\|_2 \le B_T$.
- **B2 (Slater Feasibility):** There exists a strictly feasible policy with per-round resource slack $\rho > 0$ under normalized energy, carbon, latency, and cost budgets.
- **B3 (Bounded Non-Conformity Scores):** Conformal PID scores $s_t \in [0, 1]$ with step size $\eta > 0$, integral gain $K_i \ge 0$, and bounded threshold updates $q_t \in [q_{\min}, q_{\max}]$.

**Statement:**
1. *Dynamic Regret & Knapsack Feasibility:* With discount factor $\gamma = 1 - (B_T / (d T))^{2/3}$ and primal-dual step size $\eta_\lambda = O(T^{-1/2})$, CA-DPD-LinUCB achieves dynamic regret
   $$\mathcal{R}_T = \widetilde{\mathcal{O}}\!\left(d^{2/3} B_T^{1/3} T^{2/3} + \rho^{-1}\sqrt{M T}\right)$$
   and sublinear cumulative constraint violation $\mathcal{V}_T = \widetilde{\mathcal{O}}(\rho^{-1}\sqrt{M T})$.
2. *Online Conformal PID Risk Control (P-Channel Bound vs. Integral Acceleration):* Note carefully that the CA-DPD-LinUCB regret bound assumes bounded parameter drift $B_T$ independent of the downstream selective-acceptance gate. For the online conformal gate under arbitrary distribution shift, the exact distribution-free finite-sample telescoping bound holds strictly for the **proportional (P-only) update** ($k_I = 0$, $q_{t+1} = q_t + \eta(\text{err}_t - \alpha)$):
   $$\left|\frac{1}{T}\sum_{t=1}^T \text{err}_t - \alpha\right| \le \frac{q_{\max} - q_{\min} + \eta}{\eta T}$$
   for the proportional channel (Angelopoulos et al., NeurIPS 2023), which converges to $\alpha$ as $T \to \infty$ ($O(1/(\eta T))$). Over finite post-shift windows ($T_{\text{post}} = 800$ after an abrupt $-23\text{ pp}$ accuracy shock), a small positive transient overshoot ($\approx +0.30\text{ pp}$, yielding $5.30\% \pm 0.12\%$ vs. $\alpha = 5.00\%$) is mathematically expected and strictly bounded by $(q_{\max} - q_{\min})/(\eta T_{\text{post}})$; setting a conservative design target $\alpha_{\text{design}} = 0.045$ or extending the horizon ($T_{\text{post}} = 3000$) brings empirical risk strictly below $5.00\%$.

**Proof Sketch & Derivation:**
1. Decompose per-round Lagrangian regret into (a) *primal contextual estimation error* under exponential discounting $\gamma$, which by Russac et al. (NeurIPS 2019, Thm. 2) yields $\widetilde{\mathcal{O}}(d^{2/3} B_T^{1/3} T^{2/3})$ when $\gamma$ balances variance $(1-\gamma)^{-1/2}$ against bias $B_T(1-\gamma)$, plus (b) *dual OGD regret* over $M=4$ knapsack constraints (energy, carbon, latency, cost), which by Agrawal & Devanur (NeurIPS 2016) with Slater slack $\rho > 0$ contributes $\widetilde{\mathcal{O}}(\rho^{-1}\sqrt{M T})$ to both regret and cumulative violation.
2. Summing the Conformal PID recursion $q_{t+1} - q_t = \eta(\text{err}_t - \alpha)$ from $t = 1$ to $T$ telescopes to $q_{T+1} - q_1 = \eta \sum_{t=1}^T (\text{err}_t - \alpha)$. Dividing by $\eta T$ and applying $|q_{T+1} - q_1| \le q_{\max} - q_{\min} + \eta$ immediately yields $\left|\frac{1}{T}\sum_{t=1}^T \text{err}_t - \alpha\right| \le \frac{q_{\max} - q_{\min} + \eta}{\eta T}$, independent of any i.i.d. or exchangeability assumption. $\square$

---

## Theorem 5 — Cross-Plane Non-Decomposability & C-DoW / Sleep-DoS Energy Bounds
**Assumptions:**
- **C1 (Decoupled Composition Model):** Consider any decoupled system $(R, S, P)$ where router $R$ inspects only prompt features without Plane I provenance labels $\iota(x)$, sleep manager $S$ wakes GPU tier $T_3$ upon request arrival before downstream proxy $P$ checks authorization, and $P$ enforces security only at tool-call time.
- **C2 (Adversarial Budget):** An unauthenticated adversary submits $K$ untrusted requests ($\iota(x) = \texttt{UNTRUSTED}$, no escalation Macaroon) during fossil peak $C_{\max}$ that mimic high-complexity prompts or target sleeping $T_3$ GPUs.

**Statement:**
1. Under any decoupled composition $(R, S, P)$ satisfying C1–C2, the adversary induces worst-case active + wakeup energy
   $$E_{\text{decoupled}}(K) = K \cdot \left(E_{T_3} + E_{\text{wake}}(T_3)\right), \qquad \text{CO}_{2,\text{decoupled}}(K) = E_{\text{decoupled}}(K) \cdot C_{\max}.$$
2. Under NOSIH's coupled **PCSP + PA-PCS-PMC** invariants:
   - Every unauthorized hop targeting a sleeping GPU is rejected by Plane I before `on_authorized_request_arrival(..., authorized=False)`, incurring strictly $E_{\text{wake}}^{\text{unauth}} = 0\text{ J}$ ($100\%$ elimination of Sleep-Thrashing DoS wakeup energy).
   - Every unauthenticated untrusted prompt is capped by PCSP at $T_1$ (or $T_{0\text{b}}$ when symbolic cues exist), bounding adversarial energy by $E_{\text{NOSIH}}(K) \le K \cdot E_{T_1}$ (or $K \cdot E_{T_{0\text{b}}}$), guaranteeing an energy & $\text{CO}_2$ amplification reduction factor of at least $1 - E_{T_1}/E_{T_3}$ (empirically $96.9\%$ when mixed with symbolic quarantine).
3. Because $R$ lacks $\iota(x)$ and $S$ executes before $P$ under C1, no decoupled wrapper can enforce either bound without sharing Plane I cryptographic provenance & authorization state directly inside Plane II and Plane III. $\square$

---

## Trust Boundary Note on CCEC (Auditable Accounting vs. Hardware Attestation)
Under Assumption A1–A2, `CarbonCertificateAuthority` (CCEC) provides **tamper-evident auditable Scope-2 accounting records**: once committed to `MTLog`, neither energy/CO₂ figures nor `accounting_mode` tags can be retroactively altered or truncated without breaking $O(\log N)$ Merkle inclusion/consistency proofs (across $N=240$ leaves: min 7, mean 7.93, max 8 hashes). However, recording `hardware_attestation_digest` in host software does **not** by itself prove that raw physical sensor readings were genuine against a compromised host OS; true hardware-attested sensor provenance requires a hardware root of trust (e.g., Intel TDX / AMD SEV-SNP / NVIDIA Confidential Computing with signed NVML/RAPL drivers), which lies outside our current host-TCB scope.
