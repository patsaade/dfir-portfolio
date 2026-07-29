<h1 align="center">Patrick Saade</h1>

<p align="center">
  <strong>DFIR-focused security analyst</strong> — digital forensics &amp; incident response, in the open.
</p>

<p align="center">
  <a href="https://patricksaade.com"><img alt="Website" src="https://img.shields.io/badge/patricksaade.com-3b82f6?logo=astro&logoColor=white"></a>
  <a href="https://www.linkedin.com/in/patsaade"><img alt="LinkedIn" src="https://img.shields.io/badge/LinkedIn-0A66C2?logo=linkedin&logoColor=white"></a>
  <a href="https://github.com/patsaade"><img alt="GitHub" src="https://img.shields.io/badge/GitHub-181717?logo=github&logoColor=white"></a>
  <a href="https://www.credly.com/users/patsaade"><img alt="Credly" src="https://img.shields.io/badge/Credly-FF6B00?logoColor=white"></a>
</p>

---

## 👋 About

I'm a **Senior Information Security Analyst at First American**, working the Information
Security Operations Center — detection-and-response, incident response, and detection tuning
across SIEM, cloud, endpoint, and email. I came up through the SOC at **ReliaQuest** (alert
triage → detection engineering) and ran hands-on threat response at **Red Canary** (now part
of Zscaler), doing live response and containment for confirmed endpoint threats.

Now I'm going deeper on the forensics craft and documenting it in the open at
**[patricksaade.com](https://patricksaade.com)**.

## 🔬 Focus

- **Host forensics** — registry, `$MFT`/USN/Prefetch/Shellbags, timeline reconstruction
- **Memory forensics** — Volatility 3, MemProcFS, finding malicious code in RAM
- **EDR artifact analysis** · live response & containment
- **Lab & CTF writeups** — CyberDefenders, 13Cubed, MemLabs, Magnet (public datasets only — never employer/client casework)

## 📜 Certifications

- **CISSP** (ISC2)
- **CompTIA** SecurityX (CASP+) · CySA+ · PenTest+ · Cloud+ · Server+ — [full set on Credly](https://www.credly.com/users/patsaade)
- *In pursuit of:* GCFA · GCFE · GCIH

## 🔗 Links

[Site](https://patricksaade.com) · [LinkedIn](https://www.linkedin.com/in/patsaade) · [GitHub](https://github.com/patsaade) · [Credly](https://www.credly.com/users/patsaade)

---

<details>
<summary><sub>About this repository</sub></summary>

<br>

This repo is the source for **patricksaade.com** — an **Astro + Panda CSS + MDX** site
deployed on Vercel via the `@astrojs/vercel` adapter (all routes prerendered to static HTML;
CI type-checks, tests, and builds every push). The same build also serves
**[cyberkit.win](https://cyberkit.win)**, a tools-only mirror on the same Vercel project: personal
pages (About, Certifications, Blog, Labs) redirect to the homepage there, and the nav/footer
brand swaps accordingly — every reference, tool, and drill is otherwise identical on both
domains.

```bash
npm install     # also runs `panda codegen`
npm run dev      # → http://localhost:4321
npm run build    # panda codegen + astro build
npm run check    # astro check (types/diagnostics)
npm test         # Vitest unit suite
```

Technical details: [docs/AUTHORING.md](docs/AUTHORING.md) (writing posts) ·
[docs/STYLE_GUIDE.md](docs/STYLE_GUIDE.md) (design, direction, and the OG-card/brand-asset
pipeline). Design & front-end built with AI assistance
([Claude Code](https://claude.com/claude-code)), then reviewed & refined — see
[/colophon/](https://patricksaade.com/colophon/).

</details>

<sub>Content © Patrick Saade.</sub>
