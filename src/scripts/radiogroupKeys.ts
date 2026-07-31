// @ts-nocheck — vanilla DOM client script
//
// Arrow-key navigation for every `role="radiogroup"` segmented switch, retrofitted
// site-wide in one place.
//
// WHY. These switches are `<button role="radio">`, not real `<input type="radio">`,
// so they get ZERO native keyboard behaviour: no arrow keys, and every segment is
// its own tab stop. The WAI-ARIA radiogroup pattern requires Left/Up and
// Right/Down to move between options, with the group occupying a single tab stop.
// Without it a keyboard user can still reach each button by tabbing, but the
// widget announces itself as a radiogroup and then doesn't behave like one — and
// on a group of 10 (HashCalculator's algorithm row) that is 10 tab stops to cross.
//
// 16 of the 18 radiogroups on this site had no arrow handling. Three components
// had hand-rolled their own (ToolSidebar, TagCombobox, ThemePicker) — this leaves
// those completely alone (see the `__radioKeys` guard and the `data-no-radiokeys`
// opt-out) rather than trying to unify them, because each has extra behaviour
// bound up in its own handler.
//
// Deliberately a SEPARATE script from animatedSwitch.ts even though both
// auto-wire the same selector: that one is a visual enhancement and returns early
// under `prefers-reduced-motion`, which must never take keyboard access with it.
//
// "Selection follows focus" per the ARIA pattern: moving focus activates the
// option. This calls `.focus()` then `.click()` on the target rather than
// duplicating any component's own activation logic, so whatever a given switch
// does on click keeps being the one definition of activating a segment — the same
// approach ToolSidebar's own mode switch already takes.

/** Buttons that make up the group, in DOM order. */
function optionsOf(group: HTMLElement): HTMLElement[] {
  return Array.prototype.filter.call(
    group.querySelectorAll('[role="radio"]'),
    (el: HTMLElement) => !el.hasAttribute('disabled') && el.getAttribute('aria-disabled') !== 'true',
  ) as HTMLElement[];
}

/** Index of the option that is currently active, or 0. */
function activeIndex(opts: HTMLElement[]): number {
  const i = opts.findIndex((o) => o.hasAttribute('data-active') || o.getAttribute('aria-checked') === 'true');
  return i < 0 ? 0 : i;
}

/**
 * Roving tabindex: the group is ONE tab stop, and arrows move within it.
 * Without this, a 10-option switch costs a keyboard user 10 tab presses to get
 * past — the exact problem the radiogroup pattern exists to solve.
 */
function applyRovingTabindex(group: HTMLElement): void {
  const opts = optionsOf(group);
  if (!opts.length) return;
  const active = activeIndex(opts);
  opts.forEach((o, i) => o.setAttribute('tabindex', i === active ? '0' : '-1'));
}

export function radiogroupKeys(group: HTMLElement): void {
  // Never double-bind, and never touch a group that already ships its own
  // arrow handling (ToolSidebar / TagCombobox / ThemePicker opt out explicitly).
  if ((group as any).__radioKeys || group.hasAttribute('data-no-radiokeys')) return;
  (group as any).__radioKeys = true;

  applyRovingTabindex(group);

  group.addEventListener('keydown', (e: KeyboardEvent) => {
    const key = e.key;
    if (
      key !== 'ArrowRight' && key !== 'ArrowDown' && key !== 'ArrowLeft' &&
      key !== 'ArrowUp' && key !== 'Home' && key !== 'End'
    ) return;

    const opts = optionsOf(group);
    if (opts.length < 2) return;
    // Only act when focus is actually inside the group's own options.
    const from = opts.indexOf(document.activeElement as HTMLElement);
    if (from < 0) return;

    e.preventDefault(); // stop Arrow keys from scrolling the page
    let to: number;
    if (key === 'Home') to = 0;
    else if (key === 'End') to = opts.length - 1;
    else {
      const fwd = key === 'ArrowRight' || key === 'ArrowDown';
      to = (from + (fwd ? 1 : -1) + opts.length) % opts.length; // wraps, per the ARIA pattern
    }

    const target = opts[to];
    opts.forEach((o, i) => o.setAttribute('tabindex', i === to ? '0' : '-1'));
    target.focus();
    // Selection follows focus — delegate to the component's own click handler
    // rather than reimplementing what activation means for this particular switch.
    target.click();
  });

  // A switch can also be changed by mouse, or by its own script (ModeToggle syncs
  // on the `themechange` event); keep the single tab stop pointing at whatever is
  // actually active afterwards.
  group.addEventListener('click', () => setTimeout(() => applyRovingTabindex(group), 0));
}
