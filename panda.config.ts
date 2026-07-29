import { defineConfig } from '@pandacss/dev';

export default defineConfig({
  // Whether to use css reset
  preflight: true,

  // Where to look for your css declarations
  include: ['./src/**/*.{js,jsx,ts,tsx,astro,mdx}'],

  // Files to exclude
  exclude: [],

  // Light/dark mode is signalled by a `data-mode` attribute on <html>;
  // the specific palette is set by `data-theme` (see src/themes.ts).
  conditions: {
    extend: {
      light: '[data-mode=light] &',
      dark: '[data-mode=dark] &',
    },
  },

  // Useful for theme customization
  theme: {
    extend: {
      tokens: {
        colors: {
          // Raw palette (DFIR-themed)
          blue: {
            deep: { value: '#1e40af' },
            electric: { value: '#3b82f6' },
            400: { value: '#60a5fa' },
          },
          green: {
            remediate: { value: '#16a34a' },
            highlight: { value: '#4ade80' },
          },
          slate: {
            50: { value: '#f8fafc' },
            100: { value: '#f1f5f9' },
            200: { value: '#e2e8f0' },
            300: { value: '#cbd5e1' },
            400: { value: '#94a3b8' },
            500: { value: '#64748b' },
            600: { value: '#475569' },
            700: { value: '#334155' },
            800: { value: '#1e293b' },
            900: { value: '#0f172a' },
            950: { value: '#030712' },
          },
        },
        fonts: {
          // Redaction (grade 0, clean) is the site's official typeface — body,
          // headings, display, and metadata. Georgia/Times is the serif fallback
          // so there's minimal shift while the webfont loads (see styles/fonts.css).
          sans: {
            value: 'Redaction, Georgia, "Times New Roman", "Iowan Old Style", serif',
          },
          // Degraded grade for the wordmark. Same metrics as grade 0, so it's
          // hover-swappable with no reflow.
          redaction50: {
            value: '"Redaction 50", Georgia, "Times New Roman", serif',
          },
          // Fira Mono is the site's monospace for all code-like text (code blocks,
          // inline code, paths, IOCs, commands, version hashes). See styles/fonts.css.
          mono: {
            value: '"Fira Mono", ui-monospace, "SF Mono", Menlo, Consolas, monospace',
          },
        },
        radii: {
          sm: { value: '4px' },
          md: { value: '8px' },
          lg: { value: '12px' },
          xl: { value: '16px' },
        },
        shadows: {
          card: { value: '0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.08)' },
          cardHover: { value: '0 10px 25px -5px rgba(0,0,0,0.25)' },
        },
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      recipes: {
        // One uniform "micro-tag" chip shared by the card tags across Tools,
        // Certifications, Glossary, and the ATT&CK map. `tone` carries the colour
        // semantics; `mono` switches to the monospace face (for IDs like T1566).
        // Per-page extras (absolute positioning, hover, layout) compose via css().
        tag: {
          className: 'tag',
          description: 'Small uniform tag chip used on cards site-wide.',
          base: {
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.3rem',
            flexShrink: 0,
            fontFamily: 'sans',
            // One size, chosen to fit typical chip content (single words, IDs, short
            // phrases) comfortably — no cramped text, no overflow. Content auto-sizes
            // the chip (nowrap), so longer labels just widen the pill.
            fontSize: '0.68rem',
            fontWeight: 600,
            lineHeight: 1.5,
            letterSpacing: '0.04em',
            textTransform: 'uppercase',
            px: '0.46rem',
            py: '0.14rem',
            borderRadius: 'sm',
            whiteSpace: 'nowrap',
          },
          variants: {
            tone: {
              muted: { color: 'textMuted', bg: 'bgSubtle', border: '1px solid token(colors.border)' },
              primary: {
                color: 'primary',
                bg: 'color-mix(in srgb, token(colors.primary) 12%, transparent)',
                border: '1px solid color-mix(in srgb, token(colors.primary) 30%, transparent)',
              },
              accent: {
                color: 'accent',
                bg: 'color-mix(in srgb, token(colors.accent) 12%, transparent)',
                border: '1px solid color-mix(in srgb, token(colors.accent) 35%, transparent)',
              },
            },
            mono: {
              true: { fontFamily: 'mono', textTransform: 'none', letterSpacing: '0' },
            },
          },
          defaultVariants: { tone: 'muted' },
        },
        // One uniform tile shared by every `.card-grid` on the site — Glossary, Tools,
        // Certifications, the ATT&CK map, and the D3FEND map. Fixes padding, minimum
        // height, background, border, and radius so cards can't drift smaller/bigger
        // page to page; test/card-consistency.test.ts asserts every page composes this
        // recipe instead of hand-rolling the same properties. Per-page extras (hover
        // shadow, `:target`, data-attr accents, stretched-link pseudo) compose via
        // css() after it, same pattern as `tag` above.
        card: {
          className: 'card',
          description: 'Uniform card tile used by every .card-grid page.',
          base: {
            display: 'flex',
            flexDirection: 'column',
            gap: '0.35rem',
            p: '0.7rem 0.85rem',
            minH: '4rem',
            bg: 'bgCard',
            border: '1px solid token(colors.border)',
            borderRadius: 'md',
            transition: 'border-color 200ms ease, transform 200ms ease',
            _hover: { borderColor: 'primary', transform: 'translateY(-2px)' },
          },
        },
      },
      semanticTokens: {
        colors: {
          // Light is the base value, dark overrides via `_dark`
          bg: {
            value: { base: '#ffffff', _dark: '{colors.slate.950}' },
          },
          bgSubtle: {
            value: { base: '{colors.slate.50}', _dark: '{colors.slate.900}' },
          },
          bgCard: {
            value: { base: '#ffffff', _dark: '{colors.slate.900}' },
          },
          // Soft, decorative hairline (dividers, card outlines, table rules).
          // Deliberately low-contrast; WCAG 1.4.11 exempts decorative
          // boundaries. Never the sole delineation of an interactive control.
          border: {
            value: { base: '{colors.slate.200}', _dark: '{colors.slate.800}' },
          },
          // Perceivable boundary for interactive controls — text inputs,
          // textareas, selects, outline/ghost buttons. Clears WCAG 1.4.11 (3:1)
          // against every surface in both modes; per-theme override in
          // src/themes.ts keeps that true in all 10 palettes.
          borderStrong: {
            value: { base: '{colors.slate.500}', _dark: '{colors.slate.500}' },
          },
          text: {
            value: { base: '{colors.slate.900}', _dark: '#ffffff' },
          },
          textMuted: {
            value: { base: '{colors.slate.600}', _dark: '{colors.slate.400}' },
          },
          primary: {
            value: { base: '{colors.blue.deep}', _dark: '{colors.blue.electric}' },
          },
          primaryHover: {
            value: { base: '#1e3a8a', _dark: '{colors.blue.400}' },
          },
          accent: {
            value: { base: '{colors.green.remediate}', _dark: '{colors.green.highlight}' },
          },
          codeBg: {
            value: { base: '{colors.slate.100}', _dark: '{colors.slate.900}' },
          },
          // Text/icon color to use on top of a `primary` fill (buttons, active
          // chips). Per-theme override in src/themes.ts keeps it readable on
          // light primaries (e.g. dark text on the matrix/amber greens).
          onPrimary: {
            value: { base: '#ffffff', _dark: '#ffffff' },
          },
          // Success / pass state (drill pass glyphs, satisfied test cases) —
          // `danger`'s counterpart. Pass state used to reuse `accent`, which is
          // decorative and amber/terracotta/salmon in 6 of 10 palettes, making
          // pass and fail the same warm hue and hard to tell apart. Green, so
          // the two differ by hue. Every per-theme override in src/themes.ts
          // clears 4.5:1 as normal text on bg / bgCard / bgSubtle / codeBg.
          success: {
            value: { base: '#15803d', _dark: '#86efac' },
          },
          // Error / failure state (drill fail glyphs, invalid-input messages).
          // Replaces the raw `red` CSS keyword, which only reached ~3.8-4.2:1 on
          // bgCard; every per-theme override in src/themes.ts clears 4.5:1 as
          // normal text on bg / bgCard / bgSubtle / codeBg.
          danger: {
            value: { base: '#b91c1c', _dark: '#f87171' },
          },
          // Text/icon color to use on top of a `danger` fill.
          onDanger: {
            value: { base: '#ffffff', _dark: '{colors.slate.950}' },
          },
        },
      },
    },
  },

  // Global CSS
  globalCss: {
    'html, body': {
      margin: 0,
      padding: 0,
    },
    // Background color lives on <html> (not <body>) so the fixed background
    // canvas — which sits at z-index -1 above the root bg but below content —
    // remains visible. <body> stays transparent.
    html: {
      bg: 'bg',
      transition: 'background-color 300ms ease',
    },
    body: {
      background: 'transparent',
      color: 'text',
      fontFamily: 'sans',
      lineHeight: 1.7,
      WebkitFontSmoothing: 'antialiased',
      transition: 'color 300ms ease',
    },
    '*': {
      boxSizing: 'border-box',
    },
    a: {
      color: 'inherit',
      textDecoration: 'none',
    },
    '::selection': {
      bg: 'primary',
      color: 'onPrimary',
    },
  },

  // Generate keyframe animations
  globalVars: {},

  // The output directory for your css system
  outdir: 'styled-system',

  // JSX framework is not used (Astro)
  jsxFramework: undefined,
});
