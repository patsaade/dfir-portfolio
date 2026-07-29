// DFIR theme registry — single source of truth.
// Each theme defines the full set of semantic color variables Panda emits.
// `mode` drives code-block (Shiki) light/dark and native form control rendering.
//
// Palette direction: warm, muted, pastel — each theme a distinct, readable
// concept (every text/bg pair clears WCAG AA, most AAA). Dark + light, 5 each.
//
// Contrast contract (verified per palette with the WCAG relative-luminance
// formula, against bg / bgCard / bgSubtle / codeBg — every surface the color
// can land on):
//   • text, textMuted, primary, primaryHover, accent, danger  >= 4.5:1 (1.4.3)
//   • onPrimary vs primary/primaryHover, onDanger vs danger    >= 4.5:1
//   • borderStrong                                            >= 3:1  (1.4.11)
//   • border is DECORATIVE ONLY (~1.2-1.8:1) and is exempt — never use it as
//     the sole boundary of an interactive control.
// Changing any of these values means re-deriving the whole matrix, not just
// eyeballing the one pair you touched.

export interface ThemeColors {
  bg: string;
  bgSubtle: string;
  bgCard: string;
  /** Soft, decorative hairline — dividers, card outlines, table rules. Sits at
   *  ~1.2–1.8:1 against the surfaces below it, which is fine: WCAG 1.4.11
   *  exempts purely decorative boundaries. NEVER use it as the only thing
   *  delineating an interactive control — use `borderStrong` for that. */
  border: string;
  /** Perceivable boundary for interactive controls — text inputs, textareas,
   *  selects, outline/ghost buttons, focusable chips. Tuned per palette to clear
   *  WCAG 1.4.11 (3:1) against `bg`, `bgCard`, `bgSubtle` AND `codeBg`, so the
   *  same token works on every surface a control can sit on. */
  borderStrong: string;
  text: string;
  textMuted: string;
  primary: string;
  primaryHover: string;
  accent: string;
  codeBg: string;
  /** Error / failure state (drill fail glyphs, invalid-input messages). Tuned
   *  per palette to clear 4.5:1 as NORMAL TEXT against every surface
   *  (`bg`/`bgCard`/`bgSubtle`/`codeBg`) — it replaces the raw `red` keyword,
   *  which only reached ~3.8–4.2:1. */
  danger: string;
  /** Text/icon color on a `danger` fill (destructive buttons, error badges). */
  onDanger: string;
  /** Text/icon color on a `primary` fill (buttons). Defaults to white; set a
   *  dark value for light/bright (pastel) primaries so labels stay legible. */
  onPrimary?: string;
}

export interface Theme {
  id: string;
  name: string;
  mode: 'dark' | 'light';
  blurb: string;
  colors: ThemeColors;
}

export const THEMES: Theme[] = [
  // ───────────────────────── DARK ─────────────────────────
  {
    id: 'amber',
    name: 'Amber CRT',
    mode: 'dark',
    blurb: 'The warm amber glow of a vintage phosphor terminal, cozy against a deep roasted-brown night.',
    colors: {
      bg: '#150d02',
      bgSubtle: '#1e1505',
      bgCard: '#251b08',
      border: '#4d3813',
      borderStrong: '#8a6422',
      text: '#fbe7c6',
      textMuted: '#c69d63',
      primary: '#f0a838',
      primaryHover: '#f8c463',
      accent: '#e8a23f',
      codeBg: '#1e1505',
      danger: '#e45a5a',
      onDanger: '#150d02',
      onPrimary: '#150d02',
    },
  },
  {
    id: 'vaporwave',
    name: 'Vaporwave',
    mode: 'dark',
    blurb: 'Dusty 80s pastels — a soft magenta and dreamy aqua drifting over deep indigo dusk.',
    colors: {
      bg: '#161226',
      bgSubtle: '#1f1a34',
      bgCard: '#26203f',
      border: '#3d365c',
      borderStrong: '#7469a7',
      text: '#ece7f6',
      textMuted: '#a99fc6',
      primary: '#dc92c2',
      primaryHover: '#e8abd4',
      accent: '#7ad0d6',
      codeBg: '#1f1a34',
      danger: '#e66767',
      onDanger: '#161226',
      onPrimary: '#161226',
    },
  },
  {
    id: 'forest',
    name: 'Forest Ember',
    mode: 'dark',
    blurb: 'Woodland at dusk — muted sage greens warmed by the glow of a low amber ember.',
    colors: {
      bg: '#121913',
      bgSubtle: '#19221b',
      bgCard: '#1e2921',
      border: '#37483a',
      borderStrong: '#5d7a62',
      text: '#e4ecdc',
      textMuted: '#9bb198',
      primary: '#9cc488',
      primaryHover: '#b6d6a4',
      accent: '#e3a55c',
      codeBg: '#19221b',
      danger: '#e76a6a',
      onDanger: '#121913',
      onPrimary: '#121913',
    },
  },
  {
    id: 'mauve',
    name: 'Mauve Mocha',
    mode: 'dark',
    blurb: 'Coffee-house cozy — soft mauve and lavender with a warm peach glow, steeped in dark roast.',
    colors: {
      bg: '#1b1518',
      bgSubtle: '#241d22',
      bgCard: '#2c2429',
      border: '#473b45',
      borderStrong: '#826c7e',
      text: '#ede4ec',
      textMuted: '#b8a6b6',
      primary: '#cba8de',
      primaryHover: '#dbbeec',
      accent: '#edab8d',
      codeBg: '#241d22',
      danger: '#e76969',
      onDanger: '#1b1518',
      onPrimary: '#1b1518',
    },
  },
  {
    id: 'rose',
    name: 'Rosé Dusk',
    mode: 'dark',
    blurb: 'Soft rosé twilight with a warm gold accent, hushed against a charcoal-plum night.',
    colors: {
      bg: '#1a1521',
      bgSubtle: '#231d2b',
      bgCard: '#2a2333',
      border: '#463c54',
      borderStrong: '#7d6b95',
      text: '#ece6ef',
      textMuted: '#b2a5bf',
      primary: '#e29db1',
      primaryHover: '#efb5c6',
      accent: '#e9cb8c',
      codeBg: '#231d2b',
      danger: '#e76969',
      onDanger: '#1a1521',
      onPrimary: '#1a1521',
    },
  },

  // ───────────────────────── LIGHT ─────────────────────────
  // Ordered to mirror the dark themes above — each light is the daylight
  // complement of the dark in the same position (amber↔sand, vaporwave↔mist,
  // forest↔latte, mauve↔café crème, rosé dusk↔rosé dawn).
  {
    id: 'sand',
    name: 'Sandstorm',
    mode: 'light',
    blurb: 'Sun-warmed desert paper in sand and clay, with fired terracotta and a dusty olive accent.',
    colors: {
      bg: '#f8f1e2',
      bgSubtle: '#f1e5cf',
      bgCard: '#fdf8ee',
      border: '#dcc499',
      borderStrong: '#9c7736',
      text: '#2c2414',
      textMuted: '#74613b',
      // Darkened from #a64a26 (same hue/sat, L 40.0% -> 39.0%): the old value
      // measured 4.48:1 on codeBg, a hair under WCAG 1.4.3 AA for normal text.
      primary: '#a24825',
      primaryHover: '#8a3c1d',
      accent: '#566425',
      codeBg: '#efe1c5',
      danger: '#b03629',
      onDanger: '#fdf8ee',
      onPrimary: '#fdf8ee',
    },
  },
  {
    id: 'mist',
    name: 'Lavender Mist',
    mode: 'light',
    blurb: 'A soft lavender haze of muted violet and dusty teal drifting over pale petal-white.',
    colors: {
      bg: '#f6f3fb',
      bgSubtle: '#eee8f6',
      bgCard: '#fdfbff',
      border: '#d2c6e4',
      borderStrong: '#8f71bc',
      text: '#2c2738',
      textMuted: '#635a7c',
      primary: '#6d52a7',
      primaryHover: '#5a4290',
      accent: '#36686f',
      codeBg: '#e9e2f4',
      danger: '#b3372a',
      onDanger: '#fdfbff',
    },
  },
  {
    id: 'latte',
    name: 'Matcha Latte',
    mode: 'light',
    blurb: 'Matcha-latte calm — soft muted green over warm cream, finished with a clay-terracotta accent.',
    colors: {
      bg: '#f6f3e8',
      bgSubtle: '#ece8d7',
      bgCard: '#fffef9',
      border: '#d6cdb4',
      borderStrong: '#91804f',
      text: '#232217',
      textMuted: '#5d5942',
      primary: '#4f6b2e',
      primaryHover: '#3d551f',
      // Darkened from #a5512d (same hue/sat, L 41.2% -> 39.6%): the old value
      // measured 4.48:1 on bgSubtle, just under WCAG 1.4.3 AA for normal text.
      accent: '#9f4e2b',
      codeBg: '#efead9',
      danger: '#b6382b',
      onDanger: '#fffef9',
    },
  },
  {
    id: 'paper',
    name: 'Café Crème',
    mode: 'light',
    blurb: 'Creamy café-au-lait light — soft mauve and peach over warm parchment.',
    colors: {
      bg: '#f5f1f2',
      bgSubtle: '#ebe4e8',
      bgCard: '#fffdfe',
      border: '#ddd1d8',
      borderStrong: '#99768a',
      text: '#2a2127',
      textMuted: '#6d5e68',
      primary: '#82548f',
      primaryHover: '#6b4277',
      // Darkened from #a94f38 (same hue/sat, L 44.1% -> 42.0%): the old value
      // measured 4.35:1 on bgSubtle, under WCAG 1.4.3 AA for normal text.
      accent: '#a14b35',
      codeBg: '#ede4ea',
      danger: '#b4372a',
      onDanger: '#fffdfe',
    },
  },
  {
    id: 'dawn',
    name: 'Rosé Dawn',
    mode: 'light',
    blurb: 'A blush off-white morning brushed with muted rose and quiet pine — gentle and pastel.',
    colors: {
      bg: '#fbf4f2',
      bgSubtle: '#f6e8e5',
      bgCard: '#fffafa',
      border: '#e3c8c2',
      borderStrong: '#b56d5d',
      text: '#2e252a',
      textMuted: '#765c63',
      primary: '#a4426a',
      primaryHover: '#883354',
      accent: '#2f6f64',
      codeBg: '#f4e2dd',
      danger: '#b4372a',
      onDanger: '#fffafa',
    },
  },
];

export const DARK_THEMES = THEMES.filter((t) => t.mode === 'dark');
export const LIGHT_THEMES = THEMES.filter((t) => t.mode === 'light');

export const DEFAULT_DARK = 'mauve';
export const DEFAULT_LIGHT = 'paper';

/** Map of theme id -> mode, for the inline pre-paint script. */
export const THEME_MODES: Record<string, 'dark' | 'light'> = Object.fromEntries(
  THEMES.map((t) => [t.id, t.mode]),
);

/** Map of theme id -> page bg, so the pre-paint script can keep the mobile
 *  browser-chrome `theme-color` meta in sync with the active palette. */
export const THEME_BG: Record<string, string> = Object.fromEntries(
  THEMES.map((t) => [t.id, t.colors.bg]),
);

/** CSS-var name for each color key (matches Panda's generated names).
 *  `onPrimary` is excluded — it's emitted separately (with a default) in buildThemeCss. */
const VAR_NAMES: Record<Exclude<keyof ThemeColors, 'onPrimary'>, string> = {
  bg: '--colors-bg',
  bgSubtle: '--colors-bg-subtle',
  bgCard: '--colors-bg-card',
  border: '--colors-border',
  borderStrong: '--colors-border-strong',
  text: '--colors-text',
  textMuted: '--colors-text-muted',
  primary: '--colors-primary',
  primaryHover: '--colors-primary-hover',
  accent: '--colors-accent',
  codeBg: '--colors-code-bg',
  danger: '--colors-danger',
  onDanger: '--colors-on-danger',
};

/** Build the unlayered CSS that maps each theme id to its variable overrides. */
export function buildThemeCss(): string {
  return THEMES.map((theme) => {
    const decls = (Object.keys(VAR_NAMES) as Exclude<keyof ThemeColors, 'onPrimary'>[])
      .map((key) => `${VAR_NAMES[key]}: ${theme.colors[key]};`)
      .join('');
    // onPrimary is optional in the registry; default to white.
    const onPrimary = `--colors-on-primary: ${theme.colors.onPrimary ?? '#ffffff'};`;
    return `:root[data-theme="${theme.id}"]{color-scheme:${theme.mode};${decls}${onPrimary}}`;
  }).join('\n');
}
