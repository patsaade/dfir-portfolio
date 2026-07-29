// @ts-nocheck — vanilla DOM client utility
// Smoothly animates a <details> element's open/close (height + opacity)
// instead of the native instant toggle. Used site-wide (see
// AnimatedDetails.astro, mounted once in BaseLayout) for every collapsible
// group: Tools, Glossary, Certifications, ATT&CK/D3FEND maps, the Cheat
// Sheet, and the mobile nav accordion.
//
// 0.45s — snappy but smooth (see CLAUDE.md invariant 12), matching
// `.declassify`'s own duration (motion.css) so the two finish together. On
// expand, the group's own <summary> heading additionally "declassifies" in
// step with the height reveal, reusing the exact same visual language as
// post/section titles rather than inventing a new one — every collapsible
// group opening reads as a small reveal, matching the nav dropdown's own
// font-decode. `:scope > summary > h2, h3` is a plain structural selector
// (every page happens to put its group heading directly there) so this
// works site-wide with no markup changes on any page. (This used to run at
// 1s, deliberately slow/dramatic — sped up because it read as sluggish
// rather than dramatic; still noticeably eased, not an instant snap.)
//
// No-ops under prefers-reduced-motion — the native instant toggle is already
// a fully visible, settled state, satisfying motion.css's reduced-motion
// rule without extra code here (the declassify retrigger below never runs
// either, since this whole function returns before reaching it). Only
// <summary> clicks are intercepted; programmatic opens (CollapseAll's bulk
// toggle, native fragment/`:target` auto-expand, exclusive accordion groups
// closing a sibling) still just snap — animating every path that can change
// `.open` isn't worth the added complexity for a decorative flourish.
//
// ZERO dependencies: this is a plain two-keyframe height tween, so it uses the
// platform's own `Element.animate()` (WAAPI) directly. It used to import
// `animate` from `motion/mini` — but that build is itself only a thin WAAPI
// wrapper with no physics engine, so for a fixed-duration `height: [a, b]`
// tween it added a bundled dependency and bought nothing the platform doesn't
// already give us. `Element.animate()` returns an `Animation` exposing the
// same `.finished` promise this file already relied on. See CLAUDE.md
// invariant 5 for the standing "keep client JS minimal" rule this serves.
//
// `fill: 'forwards'` + an explicit `cancel()` reproduces what motion did with
// `commitStyles()`: without the fill, the element would snap back to its
// pre-animation height for one frame between the animation ending and the
// `.finished` handler clearing the inline styles.

const DURATION_MS = 450; // see file header for why (0.45s)

export function animateDetails(details) {
  if (details.__animatedDetails) return;
  details.__animatedDetails = true;
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  const summary = details.querySelector(':scope > summary');
  if (!summary) return;
  const heading = summary.querySelector(':scope > h2, :scope > h3');

  let busy = false;
  summary.addEventListener('click', (e) => {
    e.preventDefault();
    if (busy) return;
    if (details.open) collapse();
    else expand();
  });

  function settle() {
    details.style.height = '';
    details.style.overflow = '';
    busy = false;
  }

  // A plain two-keyframe height tween on the platform's own WAAPI.
  // `fill: 'forwards'` holds the end height until the caller has finished
  // rearranging the DOM (flipping `.open`, clearing the inline height), then
  // `cancel()` drops the animation's hold — do it in that order or the
  // element flashes back to its start height for a frame in between.
  function tweenHeight(from: number, to: number, done: () => void) {
    const anim = details.animate([{ height: `${from}px` }, { height: `${to}px` }], {
      duration: DURATION_MS,
      easing: 'ease',
      fill: 'forwards',
    });
    anim.finished
      .then(() => {
        done();
        anim.cancel();
      })
      .catch(() => {
        /* cancelled out from under us — nothing to settle */
      });
  }

  function collapse() {
    busy = true;
    const startH = details.offsetHeight;
    details.style.overflow = 'hidden';
    details.style.height = `${startH}px`;
    details.offsetHeight; // force reflow so the browser registers the start height
    const endH = summary.offsetHeight;
    tweenHeight(startH, endH, () => {
      details.open = false;
      settle();
    });
  }

  function expand() {
    busy = true;
    const startH = details.offsetHeight;
    details.open = true;
    const endH = details.scrollHeight;
    details.style.overflow = 'hidden';
    details.style.height = `${startH}px`;
    details.offsetHeight; // force reflow

    // Restart the heading's declassify decode on every expand, not just the
    // first — a plain class re-add wouldn't restart an already-finished CSS
    // animation, so remove it, force a reflow to commit the "off" state,
    // then re-add it.
    if (heading) {
      heading.classList.remove('declassify');
      heading.offsetWidth; // force reflow
      heading.classList.add('declassify');
    }

    tweenHeight(startH, endH, settle);
  }
}
