// @ts-nocheck — vanilla DOM client utility
// Animates a segmented-switch's active-position indicator — a "thumb" that
// slides behind the active segment — on click. Used site-wide (see
// AnimatedSwitch.astro, mounted once in BaseLayout) for every
// role="radiogroup" segmented switch: ModeToggle, ViewToggle,
// HashCalculator's Input source switch, IocExtractor's fang row,
// DorkBuilder's engine row, and ThemePicker's two vertical palette lists —
// see AnimatedSwitch.astro's header for the retrofit contract; nothing below
// needs to change for a future switch to pick it up. Slides horizontally
// (translateX) by default; a group with `aria-orientation="vertical"` (only
// ThemePicker's palette lists today) slides vertically (translateY) instead
// — same attribute those lists already carry for their own arrow-key nav, so
// there's no separate opt-in convention to remember.
//
// 150ms/ease-out — deliberately snappy (matches this codebase's existing
// "fast UI feedback" rhythm — segBtn/modeBtn/engineBtn's own `transition:
// all 150ms ease` hover states use the exact same duration), NOT the
// ~0.45-0.5s timing this codebase uses elsewhere for reveals (animatedDetails.ts,
// the nav dropdown's `.nav-more-menu`, `declassify-hero`). Those are staged,
// once-per-load (or once-per-open) reveals meant to read as a decode. A
// switch thumb is direct-manipulation UI feedback tracking a click that
// already happened — it has to feel immediate, not staged, or the control
// reads as laggy. (Originally shipped at 220ms — dropped to 150ms after it
// still read as sluggish once the double-indicator bug below was found and
// fixed; a slower thumb was partly masking/competing with the second
// indicator rather than the duration alone being the problem.)
//
// IMPORTANT — suppressing the redundant per-button indicator: every switch's
// button already carries its own `&[data-active]` background/border/shadow
// (the pre-existing, JS-free, fully-accessible flat color swap). Once this
// script arms a thumb, that per-button background becomes a SECOND,
// independently-timed indicator (its own 150ms CSS `transition: all`) racing
// the thumb's animate() call — the two don't share a clock, so for a window
// mid-transition you'd see the newly-active button's own background already
// fully lit via CSS while the thumb (also fully-colored) is still visibly
// sliding across the *other*, still-unselected buttons underneath: a
// double-indicator flicker that reads as broken, not as one switch. The fix
// is NOT to delete the per-button background from each component's CSS —
// that background is the only indicator reduced-motion/no-JS visitors ever
// see (this script returns before creating anything under reduced motion —
// see below), so removing it would break that fallback. Instead, once the
// thumb has actually been placed at a real position for the first time —
// inside place(), past its `if (!w) return` guard, NOT unconditionally right
// after the thumb element is created — this script sets `data-switch-armed`
// on the GROUP; a single hand-written global rule in motion.css —
// `[data-switch-armed] [role='radio'][data-active] { background: transparent;
// border-color: transparent; box-shadow: none; }` — suppresses ONLY the
// background/border/shadow (never the active-state text/icon `color`, which
// stays a normal, non-competing 150ms fade layered on top of the sliding
// thumb) and ONLY while a thumb actually exists to replace it. This is a
// single shared rule, not a per-consumer Panda override: the natural way to
// author this in each component's own css() — a nested condition like
// `{'[data-switch-armed] &': {'&[data-active]': {...}}}` — does NOT compile
// to a real compound selector (confirmed by inspecting the compiled CSS
// directly; it collapses to a plain `.btn[data-active]` rule with the
// ancestor check only baked into the generated class name, never into an
// actual selector, so it unconditionally won on source order regardless of
// whether the group was armed). No-JS/reduced-motion visitors never see
// `data-switch-armed` at all, so their experience is byte-for-byte unchanged
// from before this feature existed.
//
// No-ops entirely under prefers-reduced-motion — mirrors animatedDetails.ts's
// own shape (idempotent init guard, then an immediate reduced-motion bailout
// before touching the DOM at all). Each switch's plain `[data-active]` color
// swap, already rendered server-side with no JS required, is a fully correct
// and fully accessible control on its own — the thumb is a pure enhancement
// layer painted in behind the button content, never required for
// correctness. A belt-and-suspenders `.switch-thumb { transition: none }`
// rule still lives in motion.css's reduced-motion block (see that file) in
// case anything outside this guard ever adds the class.
//
// Thumb coloring is *not* hardcoded per component: on every placement this
// clones the currently-active button's own resolved background/border/
// shadow/radius via getComputedStyle and copies it onto the thumb, so colors
// always match that switch's own theme exactly — including staying in sync
// across a live palette change (see the `themechange` listener below) — with
// zero color-matching code required in any consuming component. Combined
// with the group being the thumb's only required markup change (see
// AnimatedSwitch.astro), a future switch needs nothing beyond
// `position: 'relative', zIndex: 0` on its track.
//
// Groups can be hidden (`display: none`) at the moment this runs — every
// WorkspaceShell-based tool (Hash Calculator, IOC Extractor, Dork Builder)
// stays hidden until its OWN script marks it ready, and this script's mount
// point in BaseLayout runs before any of those, so `place()` reads 0 for
// offsetLeft/offsetWidth on the first pass. A ResizeObserver on the group
// re-places the thumb (unanimated) whenever its size changes — including the
// display:none → flex flip — so the thumb self-corrects the instant the
// track actually becomes visible, without this script needing to run after
// every consumer's own script. This is exactly why `data-switch-armed` is
// set inside `place()` on its first SUCCESSFUL placement rather than
// unconditionally at setup: if it were set up front, a group still hidden
// at that point would have its fallback indicator suppressed with nothing
// yet in its place — neither indicator visible — for however long the
// ResizeObserver takes to fire. Gating the attribute on real placement
// means the fallback stays visible right up until the thumb has something
// real to show, so there is never a frame with no visible indicator at all.
//
// ZERO dependencies: the thumb's slide is a plain two-keyframe transform/size
// tween, so it uses the platform's own `Element.animate()` (WAAPI) directly.
// This used to import `animate` from `motion/mini` — but that build is itself
// only a thin WAAPI wrapper with no physics engine, so for a fixed-duration
// tween it added a bundled dependency and bought nothing the platform doesn't
// already provide. Everything below that depends on WAAPI semantics works
// identically on a native Animation: `thumb.getAnimations()` still returns it,
// `.finish()` still forces it to its end value, and getComputedStyle() still
// reflects the live interpolated value of a running animation (which is what
// makes a mid-flight retarget redirect smoothly rather than jumping).
//
// One deliberate difference from motion: motion committed the final value to
// inline style and dropped the animation on finish (`commitStyles()`), whereas
// a bare native animation reverts to the underlying inline style the instant
// it ends. So the tween below runs with `fill: 'forwards'` (holds the end
// value, no one-frame snap-back) and `settleThumb()` does the commit-then-
// `cancel()` by hand — see that function.

const DURATION_MS = 150; // see file header for why this differs from the ~450-500ms reveals
const EASING = 'ease-out';

export function animateSwitch(group) {
  if (group.__animatedSwitch) return;
  group.__animatedSwitch = true;
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  const buttons = Array.prototype.filter.call(group.children, function (el) {
    return el.getAttribute && el.getAttribute('role') === 'radio';
  });
  if (buttons.length < 2) return;

  const vertical = group.getAttribute('aria-orientation') === 'vertical';

  const thumb = document.createElement('span');
  thumb.className = 'switch-thumb';
  thumb.setAttribute('aria-hidden', 'true');
  thumb.style.position = 'absolute';
  if (vertical) {
    // Spans the track's full width, top pinned; JS below animates `height`
    // and a translateY to slide it down the column.
    thumb.style.left = '0';
    thumb.style.right = '0';
    thumb.style.top = '0';
  } else {
    // Spans the track's full height, left pinned; JS below animates `width`
    // and a translateX to slide it across the row.
    thumb.style.top = '0';
    thumb.style.bottom = '0';
    thumb.style.left = '0';
  }
  thumb.style.zIndex = '-1'; // group carries position:relative + z-index:0 (its own stacking
  // context), so a negative z-index here reliably paints below the group's
  // other children — the buttons — regardless of whether they're positioned
  // themselves. No button CSS changes needed.
  thumb.style.pointerEvents = 'none';
  // group is the first (and only) insertion point this script requires on
  // every consuming component — see file header.
  group.insertBefore(thumb, group.firstChild);

  function activeButton() {
    for (let i = 0; i < buttons.length; i++) {
      if (buttons[i].hasAttribute('data-active')) return buttons[i];
    }
    return buttons[0];
  }

  // Clones the active button's own resolved visual treatment onto the thumb
  // — background, border, shadow, corner radius — so the thumb is always a
  // pixel-for-pixel match for that switch's own `[data-active]` styling,
  // with no per-component color code and no drift if a theme's tokens
  // change. Colors swap instantly (matching the flat, non-animated
  // `[data-active]` convention) — only position/size animate.
  //
  // Must read the button's color with `data-switch-armed` temporarily OFF.
  // That attribute is what suppresses the active button's own (redundant)
  // background via the shared `[data-switch-armed] [role='radio'][data-active]`
  // rule in motion.css — so once the group is armed (true for every call
  // after the first), reading
  // getComputedStyle(btn) straight would read back that already-suppressed
  // *transparent* value instead of the real color the thumb is supposed to
  // clone, permanently blanking the thumb on the very next reposition (any
  // click, ResizeObserver fire, or theme change).
  //
  // Must ALSO read with the button's own `transition: all 150ms` (its
  // `&[data-active]` background swap) temporarily disabled. The very first
  // time this runs — on page load — the consuming component's own setup
  // script (e.g. ModeToggle's sync()) sets `data-active` on the button
  // *synchronously*, which starts that CSS transition from transparent
  // toward the real color; this function then runs one requestAnimationFrame
  // later and can catch that transition still mid-flight. `getAnimations()
  // [].finish()` was tried first to settle it before reading, but a
  // just-started CSS transition isn't guaranteed to be registered as a
  // running Animation by the very next frame in every engine — so finish()
  // can be a no-op while the transition is still live, silently cloning
  // whatever partial (sometimes still fully transparent) frame it's on onto
  // the thumb, permanently. This is the actual mechanics behind "system
  // doesn't show the selector by default": confirmed by direct inspection —
  // disabling the transition and forcing a reflow before reading reliably
  // recovers the real color where `getAnimations().forEach(finish)` did not.
  // Toggling `transition: none` off and back on around BOTH the unarm and
  // the read (restored only after re-arming below) sidesteps the race
  // entirely: it cancels any in-flight transition outright and forces the
  // plain settled cascade value, independent of Animation-object timing —
  // and keeping it off across the re-arm step too avoids a second, reverse
  // flash-transition as the suppression rule re-applies. getComputedStyle()
  // forces a synchronous recalc, so this whole dance never paints an
  // intermediate frame — no visible flicker, just an accurate read.
  function syncColors(btn) {
    const prevTransition = btn.style.transition;
    btn.style.transition = 'none';
    const wasArmed = group.hasAttribute('data-switch-armed');
    if (wasArmed) group.removeAttribute('data-switch-armed');
    void btn.offsetWidth; // force the synchronous recalc the override above needs
    const s = getComputedStyle(btn);
    thumb.style.backgroundColor = s.backgroundColor;
    thumb.style.borderRadius = s.borderRadius;
    thumb.style.borderWidth = s.borderWidth;
    thumb.style.borderStyle = s.borderStyle;
    thumb.style.borderColor = s.borderColor;
    thumb.style.boxShadow = s.boxShadow;
    if (wasArmed) group.setAttribute('data-switch-armed', '');
    btn.style.transition = prevTransition;
  }

  // Reads the thumb's own live rendered position/size along the active axis
  // — including mid-animation, since getComputedStyle reflects the current
  // interpolated value of a running Web Animation — so a rapid second click
  // redirects smoothly from wherever the thumb currently is, not from a
  // stale previously-recorded target.
  function currentTranslate() {
    const t = getComputedStyle(thumb).transform;
    if (!t || t === 'none') return 0;
    const parts = t
      .slice(t.indexOf('(') + 1, -1)
      .split(',')
      .map(function (n) {
        return parseFloat(n);
      });
    // matrix(a, b, c, d, tx, ty) — translateX lives at index 4, translateY at index 5.
    if (parts.length < 6) return 0;
    return (vertical ? parts[5] : parts[4]) || 0;
  }
  function currentSizePx() {
    // getBoundingClientRect(), not getComputedStyle(): border-box, matching
    // the offsetWidth/offsetHeight values place() writes.
    return thumb.getBoundingClientRect()[vertical ? 'height' : 'width'] || 0;
  }

  // Native equivalent of what motion/mini used to do for us on finish
  // (`commitStyles()` + drop the animation). A `fill: 'forwards'` animation
  // keeps overriding the element's own inline style forever once it ends, so
  // it MUST be cancelled — but cancelling first would snap the thumb back to
  // whatever stale inline transform/size predates it. So: force the animation
  // to its end value, read that settled value back off the computed style,
  // write it to inline style, and only then cancel. Net effect is identical
  // to the old commitStyles() behaviour, with no intermediate frame.
  //
  // Deliberately synchronous — place() calls this and then immediately either
  // reads the position (animated branch) or writes new inline values
  // (unanimated branch); doing the commit in an async `.finished` handler
  // instead would let a stale handler land *after* those writes and clobber
  // them.
  function settleThumb() {
    const anims = thumb.getAnimations();
    if (!anims.length) return;
    anims.forEach(function (a) {
      try {
        // Same orphaned-animation guard as before: an animate() call started
        // around a View Transition capture can get stuck mid-flight and never
        // reach its target (observed frozen at a fixed frame indefinitely).
        // Finishing here guarantees each placement starts from a real,
        // settled position rather than a frozen midpoint.
        // finish() then commitStyles() writes the animation's own COMPUTED end
        // values to inline style — which is exactly what motion/mini's
        // commitStyles did, and why this must not be hand-rolled as a
        // getComputedStyle() read/write instead: `boxSizing: border-box` is
        // global (panda.config.ts), so `getComputedStyle(thumb).width` resolves
        // to the CONTENT box while every value place() writes is
        // `btn.offsetWidth`, a BORDER-box value. syncColors() clones the active
        // button's 1px border onto the thumb, so reading computed style back
        // would shrink the thumb by 2px on every settle.
        a.finish();
        a.commitStyles();
        a.cancel();
      } catch (e) {
        /* ignore */
      }
    });
  }

  function place(animated) {
    const btn = activeButton();
    const size = vertical ? btn.offsetHeight : btn.offsetWidth;
    if (!size) return; // group is currently hidden (display:none) — ResizeObserver retries
    const pos = vertical ? btn.offsetTop : btn.offsetLeft;
    // Same family of bug as syncColors()'s transition-bypass above, applied to
    // the thumb's OWN slide animation instead of the button's color transition: an
    // animate() call started around the same time as a View Transition capture can
    // get orphaned mid-flight and never reach its target — observed stuck
    // indefinitely at a fixed intermediate frame (e.g. 43ms into a 150ms
    // animation, forever). Without settling it here, currentTranslate()/
    // currentSizePx() below would keep reading that frozen midpoint as the "from"
    // position for every subsequent placement, so the thumb could drift to or stay
    // at the wrong spot across clicks instead of reliably landing on the active
    // segment — this is the actual mechanics behind the toggle's thumb not
    // tracking the current selection. settleThumb() guarantees each placement
    // starts from a real, settled position (and, since the tween now runs with
    // `fill: 'forwards'`, that the previous animation is no longer overriding the
    // inline styles the unanimated branch below writes).
    settleThumb();
    syncColors(btn);
    // Suppresses each button's own (now-redundant) [data-active] background —
    // see file header's "IMPORTANT" section. Set only here, on the thumb's
    // FIRST successful placement — not unconditionally at setup time above —
    // so a group that's still hidden (WorkspaceShell tools stay display:none
    // until their own script marks them ready) never has its fallback
    // indicator suppressed before the thumb has an actual position to show
    // in its place. Setting this unconditionally at setup previously left a
    // real "neither indicator visible" gap whenever a switch's group was
    // still hidden when this script ran (its own component script hadn't
    // revealed it yet) and something (a fast reflow, a hidden-tab throttle)
    // caused the ResizeObserver retry to be delayed — this is what made the
    // IOC Extractor's fang switch render with no visible active indicator.
    group.setAttribute('data-switch-armed', '');

    const axis = vertical ? 'Y' : 'X';
    const dim = vertical ? 'height' : 'width';
    if (animated) {
      const from = currentTranslate();
      const fromSize = currentSizePx();
      const fromFrame = { transform: `translate${axis}(${from}px)` };
      const toFrame = { transform: `translate${axis}(${pos}px)` };
      fromFrame[dim] = `${fromSize}px`;
      toFrame[dim] = `${size}px`;
      // `fill: 'forwards'` holds the end value instead of reverting to the
      // (now stale) inline style for a frame — see settleThumb() above, which
      // is what eventually commits it and drops the animation.
      thumb.animate([fromFrame, toFrame], {
        duration: DURATION_MS,
        easing: EASING,
        fill: 'forwards',
      });
    } else {
      thumb.style.transform = `translate${axis}(${pos}px)`;
      thumb.style[dim] = `${size}px`;
    }
  }

  // Initial placement: instant, never animated — a slide-in on page load
  // would be a jarring first impression.
  //
  // Deferred to the next frame for the exact same reason the click and
  // themechange listeners are: this script runs generically for every
  // role="radiogroup" on the page, so its execution order relative to a
  // specific consumer's OWN setup script (e.g. ModeToggle's sync(), which is
  // what actually sets data-active for the very first time from getMode() —
  // a *direct* call, not something dispatched via 'themechange') isn't
  // guaranteed — Astro/Vite bundles per-component scripts together, and
  // which one's top-level code runs first depends on the bundle's own
  // module graph, not the components' render order in the template. If this
  // ran first, activeButton() would find no button with data-active yet and
  // fall back to buttons[0] — often the right button by coincidence (e.g.
  // "system" is first and also the default mode) — but syncColors() would
  // still read every button's *inactive* (transparent) style, since none of
  // them have [data-active] applied yet either. And because sync()'s first
  // call is direct rather than themechange-triggered, nothing would ever
  // re-place the thumb afterward — leaving it permanently uncolored on load
  // any time this raced ahead of the consumer's own initial sync. This is
  // exactly the "system doesn't show the selector by default" symptom.
  requestAnimationFrame(function () {
    place(false);
  });

  if (window.ResizeObserver) {
    const ro = new ResizeObserver(function () {
      place(false);
    });
    ro.observe(group);
  }

  // Keeps thumb colors in sync with a live palette/mode change even when the
  // change didn't come from clicking *this* switch (e.g. the ThemePicker,
  // not ModeToggle, changing the active palette) — window.__theme dispatches
  // this on every change (see CLAUDE.md invariant 4).
  //
  // Deferred to the next frame for the exact same reason the click handler
  // below is: ModeToggle's own 'themechange' listener (which is what actually
  // moves `data-active` to the new button) is a SEPARATE, independent
  // listener on the same event — and this one isn't guaranteed to run after
  // it. Reading data-active synchronously inside the same dispatch could
  // catch it *before* ModeToggle's own listener has updated it, so place()
  // would reposition/recolor the thumb for the button that was active a
  // moment ago, not the one the mode actually just changed to. This is what
  // made the mode toggle's active segment intermittently show the wrong
  // button after a click or an OS theme change — a same-tick race, not a
  // stuck animation (see syncColors()'s transition-bypass above for the
  // separate, already-fixed frozen-transition case).
  document.addEventListener('themechange', function () {
    requestAnimationFrame(function () {
      place(false);
    });
  });

  // Re-place the thumb the instant a button's own `data-active` actually
  // changes. This used to be a per-button click listener instead (deferred a
  // frame so it always ran after the component's own click handler had set
  // the new `data-active`) — replaced because that approach raced ModeToggle
  // specifically: a click there also runs window.__theme.setMode(), which
  // wraps the DOM update in document.startViewTransition() (the full-page
  // theme-wipe, see BaseHead.astro's applyAnimated()) — a second click fired
  // before that transition settles calls skipTransition() on the first one,
  // and that interaction could leave the click listener's scheduled place()
  // reading data-active before the second click's own update had actually
  // landed, stranding the thumb at the *previous* selection even though the
  // page had already switched modes (the button's own icon color updated
  // correctly regardless, since that's a plain CSS attribute selector with
  // no timing dependency — only the thumb, and the color cloned from it,
  // stayed stuck). A MutationObserver has no such race: it fires once per
  // batch of attribute changes no matter what caused them or how many
  // happened in a row, and always reads whatever data-active *currently* is
  // at delivery time — necessarily the final state after all synchronous
  // click handling (of however many rapid clicks) has already completed.
  // This is also why IOC Extractor's fang-row switch and every other switch
  // that doesn't trigger a page-wide transition never showed this bug: their
  // click listener's own next-frame callback never had anything else in
  // flight to race against. A rapid repeat click retargeting the thumb
  // mid-flight is still correct, expected UX (the next place() settles the
  // in-flight animation and re-reads the thumb's current live position, so
  // the new tween starts from wherever it actually was — see
  // currentTranslate()/currentSizePx() above) — no debounce here; that hard
  // rule (CLAUDE.md invariant 12) is for toggles that fully reverse each
  // other, not a multi-position switch redirecting mid-slide.
  const activeAttrObserver = new MutationObserver(function () {
    place(true);
  });
  buttons.forEach(function (b) {
    activeAttrObserver.observe(b, { attributes: true, attributeFilter: ['data-active'] });
  });
}
