# Gemini Image Generation Prompt

## Prompt

Create a 1200x630 pixel dark cybersecurity-themed infographic visual for a LinkedIn post about a Python supply chain security audit tool called "pyenv-audit".

**Overall aesthetic**: Dark background (deep navy/charcoal, almost black with a subtle blue undertone), clinical and precise like a threat analysis dashboard or forensic investigation board. Think: Bloomberg terminal meets CERN data visualization. The tone is serious, technical, and sophisticated -- not gamified or cartoonish.

**Layout (left to right)**:

**Left third**: A honeycomb/hexagonal grid of ~50-60 small nodes representing Python packages. Most nodes are dim (dark gray outlines, barely visible), representing safe packages. 6-8 nodes are highlighted in amber/gold with a subtle glow, representing packages with HIGH severity vulnerabilities. 2 nodes are highlighted in a muted red, representing CRITICAL findings. Thin dashed lines connect the threat nodes to each other, like threads on a forensic evidence board.

**Center/Right**: The text "pyenv-audit" in a clean, thin, modern sans-serif font (similar to Jura or Inter Light), white text with the hyphen and "audit" in amber/gold. Below it in small, dim gray text: "Security audit for all your pyenv Python environments".

Below the title, a minimalist horizontal bar chart showing vulnerability distribution:

- CRITICAL: 2 (short red bar)
- HIGH: 6 (medium amber/gold bar)
- MODERATE: 15 (longer muted olive bar)
- LOW: 13 (longest dim gray bar)
Labels in small monospaced font. Numbers at the end of each bar.

Below the chart, four large statistics in a row: "59 packages scanned", "36 advisories matched", "8 HIGH+ findings" (the 8 in amber), "23 CVE IDs enriched".

**Bottom strip**: A thin dark panel with small monospaced text: "github.com/jeanremacle/pyenv-audit" on the left, "DATA: osv.dev | pypi.org/advisory-db" on the right. A thin amber line separates this strip from the main content.

**Top edge**: A thin amber/gold accent line across the full width.

**Scattered detail**: Faint CVE identifiers (like "CVE-2025-58367", "CVE-2026-33634", "GHSA-8p5q") floating in small monospaced text at very low opacity, like forensic specimen labels. One of them ("CVE-2026-33634", the LiteLLM CVE) should be slightly more visible with a subtle amber border.

**Bottom right corner**: Faint concentric circles suggesting a radar/scanning animation, in very dim cyan.

**Color palette**: Strictly limited to deep navy-black background, amber/gold (#F2B80F) as primary accent, white at various opacities for text hierarchy, muted red for critical markers, dim cyan for subtle decoration. No bright blues, no gradients, no glossy effects.

**Typography**: All text in thin, modern fonts. Monospaced for technical labels (like IBM Plex Mono or JetBrains Mono). Clean sans-serif for the title. No decorative fonts.

**Style**: Ultra-clean, data-dense but breathing. The image should look like a frame captured from a real-time threat monitoring dashboard. Professional enough for a senior engineer's LinkedIn post. No clip art, no icons, no stock photo elements, no AI-generated faces. Pure data visualization aesthetic.

**Do NOT include**: Padlock icons, shield icons, snake/Python logos, cartoon hackers, binary code rain, generic "cyber" imagery. Keep it abstract and data-driven.
