// @ts-nocheck — vanilla DOM client utility
// Generic "session persistence" for the DFIR interactive tool pages — saves
// whatever a visitor typed/selected into localStorage and silently restores
// it the next time they land on the same tool page, plus a reset-to-defaults
// hook. Unlike animatedDetails.ts/animatedSwitch.ts (auto-mounted once in
// BaseLayout, scanning the whole document for a structural pattern that
// repeats site-wide), this isn't auto-mounted — each tool component calls
// `persistToolSession({...})` itself, once, from its own bundled <script>,
// since which fields exist and what "reset" means is entirely tool-specific
// (see ToolSessionConfig below). That wiring is a separate, later phase —
// this file only needs to exist with a stable exported signature.
//
// Storage key: `toolsession:<pathname>` — one flat localStorage key per tool
// page (trailing slash included, per this site's trailingSlash:'always'
// config), mirroring ListFilter.astro's own `listfilter:<pathname>` key
// (same precedent, see that file). One JSON blob per page:
// `{ fields: { [name]: value }, extra?: <serialize() snapshot> }`. Written
// on a debounced timer (400ms default) and removed outright on reset —
// never overwritten with `{}` — same "removeItem, not an empty write"
// convention ListFilter uses for its own idle state.
//
// Auto-binding: every descendant of `root` carrying `data-session-field="x"`
// is picked up automatically —
//   - <input>/<textarea>/<select>   -> .value
//   - <input type="checkbox">       -> .checked
//   - <input type="file">           -> skipped, with a console.warn (file
//     contents/handles can't round-trip through localStorage — and
//     shouldn't; see privacy.astro's disclosure) so a future tool that tags
//     a file input notices immediately in dev instead of silently no-op'ing.
//   - a `role="radiogroup"` wrapper carrying `data-session-field` -> the
//     segmented-switch pattern used site-wide (ModeToggle, ViewToggle,
//     HashCalculator's Input source switch, IocExtractor's fang row,
//     DorkBuilder's engine row — see animatedSwitch.ts) of one
//     `role="radio"` button per option, one carrying `data-active`. Every
//     one of those buttons already carries exactly one *other* data-*
//     attribute naming its option (`data-mode-pref`, `data-view-btn`,
//     `data-ioc-fang`, `data-engine-btn`, `data-hash-mode`, ...) — the
//     attribute name differs per switch, so rather than hardcode any one of
//     them, this module discovers it generically per group: the first
//     data-* attribute on a button that isn't one of the known
//     non-identifying ones (`data-active`, `data-sound`, `data-switch-armed`
//     — all structural/decorative, not the option's own name) is treated as
//     that group's value attribute. Restoring re-clicks the matching button
//     for real (`.click()`), never by poking `data-active` directly, so the
//     tool's own existing click handler re-runs untouched and every other
//     side effect it has (re-rendering output, animatedSwitch's thumb, that
//     component's own unrelated localStorage write, etc.) happens exactly as
//     if the visitor had clicked it themselves.
//
// Every localStorage call is wrapped in try/catch (Safari private mode,
// quota errors, an extension blocking storage, etc. all just no-op) — same
// rule as every other stateful control on this site (ModeToggle,
// ThemePicker, SoundToggle, ToolSidebar, ListFilter).
//
// Applying restored values on load (dispatching input/change, or
// .click()-ing a radio option) happens with a `hydrating` flag held for the
// whole pass, so the very listeners those dispatches trigger don't
// immediately re-persist a blob identical to the one just read back —
// harmless either way, but pointless churn on every page load.

export interface ToolSessionConfig {
  /** Container to scan for data-session-field="…" elements. */
  root: Element;
  /** Selector (resolved against `root`) for this tool's "reset" button. */
  resetButton?: string;
  /** Extra tool-specific state to snapshot alongside the auto-bound fields
   *  (e.g. a wizard step, a generated-but-not-field-backed value). Called on
   *  every save; its return value must round-trip through JSON. */
  serialize?: () => any;
  /** Receives the stored `extra` snapshot back on load — only called when
   *  there IS a stored blob. Never called on a fresh visit or after a
   *  reset (there's nothing to restore in either case). */
  restore?: (data: any) => void;
  /** Custom teardown for state `serialize`/`restore` cover that a plain
   *  field reset can't reach (e.g. collapsing a wizard back to step one). */
  onReset?: () => void;
  /** Debounce window for the auto-save, in ms. Default 400. */
  debounceMs?: number;
}

export interface ToolSessionHandle {
  /** Flushes any pending debounced write immediately. */
  save(): void;
  /** Clears the stored blob, restores every bound field to its native
   *  default (a plain field's own defaultValue/defaultChecked, or a
   *  radiogroup's initial selection as captured at bind time), and calls
   *  `onReset()`. */
  reset(): void;
}

// Structural/decorative data-* attributes every switch button may carry
// that are NOT the attribute naming its option — see file header.
const NON_IDENTIFYING_RADIO_ATTRS = { 'data-active': 1, 'data-sound': 1, 'data-switch-armed': 1 };

function fireEvents(el, types) {
  types.forEach((t) => {
    try {
      el.dispatchEvent(new Event(t, { bubbles: true }));
    } catch (e) {
      /* ignore */
    }
  });
}

function radioButtons(group) {
  return Array.prototype.filter.call(group.children, (el) => el.getAttribute && el.getAttribute('role') === 'radio');
}

// The one data-* attribute (besides the known non-identifying ones) every
// button in the group shares — see file header. Returns null if none of the
// buttons carry a usable one (a switch shape this module doesn't recognize).
function radioValueAttr(buttons) {
  for (let i = 0; i < buttons.length; i++) {
    const attrs = buttons[i].attributes;
    for (let j = 0; j < attrs.length; j++) {
      const name = attrs[j].name;
      if (name.indexOf('data-') === 0 && !NON_IDENTIFYING_RADIO_ATTRS[name]) return name;
    }
  }
  return null;
}

function radioActiveValue(group, attrName) {
  const buttons = radioButtons(group);
  for (let i = 0; i < buttons.length; i++) {
    if (buttons[i].hasAttribute('data-active')) return buttons[i].getAttribute(attrName);
  }
  return null;
}

function radioButtonForValue(group, attrName, value) {
  const buttons = radioButtons(group);
  for (let i = 0; i < buttons.length; i++) {
    if (buttons[i].getAttribute(attrName) === value) return buttons[i];
  }
  return null;
}

// Builds the bound-field list from every data-session-field element under
// root. Each entry exposes a uniform get/apply/reset/listen shape so the
// rest of the module never needs to branch on which of the four kinds it is.
function bindFields(root) {
  const out = [];
  const els = Array.prototype.slice.call(root.querySelectorAll('[data-session-field]'));

  els.forEach((el) => {
    const name = el.getAttribute('data-session-field');
    if (!name) return;

    if (el.getAttribute('role') === 'radiogroup') {
      const buttons = radioButtons(el);
      const attrName = radioValueAttr(buttons);
      if (!attrName) {
        console.warn(`[toolSession] radiogroup field "${name}" has no identifying data-* attribute on its buttons; skipping`);
        return;
      }
      const initialValue = radioActiveValue(el, attrName);
      out.push({
        name,
        get: () => radioActiveValue(el, attrName),
        apply(value) {
          if (typeof value !== 'string') return;
          const btn = radioButtonForValue(el, attrName, value);
          if (btn && !btn.hasAttribute('data-active')) btn.click();
        },
        reset() {
          if (initialValue == null) return;
          const btn = radioButtonForValue(el, attrName, initialValue);
          if (btn && !btn.hasAttribute('data-active')) btn.click();
        },
        listen(fn) {
          // A click on a child button bubbles to the wrapper — one listener
          // here covers every option, matching animatedSwitch.ts's own
          // direct-children convention for what counts as "a button in this
          // group".
          el.addEventListener('click', (e) => {
            const t = e.target && e.target.closest ? e.target.closest('[role="radio"]') : null;
            if (t && el.contains(t)) fn();
          });
        },
      });
      return;
    }

    const tag = el.tagName;
    if (tag === 'INPUT' && el.type === 'file') {
      console.warn(`[toolSession] input[type=file] field "${name}" can't be persisted to localStorage; skipping`);
      return;
    }
    if (tag === 'INPUT' && el.type === 'checkbox') {
      out.push({
        name,
        get: () => el.checked,
        apply(value) {
          if (typeof value !== 'boolean') return;
          el.checked = value;
          fireEvents(el, ['input', 'change']);
        },
        reset() {
          el.checked = el.defaultChecked;
          fireEvents(el, ['input', 'change']);
        },
        listen(fn) {
          el.addEventListener('input', fn);
          el.addEventListener('change', fn);
          el.addEventListener('click', fn);
        },
      });
      return;
    }
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') {
      out.push({
        name,
        get: () => el.value,
        apply(value) {
          if (typeof value !== 'string') return;
          el.value = value;
          fireEvents(el, ['input', 'change']);
        },
        reset() {
          if (tag === 'SELECT') {
            Array.prototype.forEach.call(el.options, (o) => {
              o.selected = o.defaultSelected;
            });
          } else {
            el.value = el.defaultValue;
          }
          fireEvents(el, ['input', 'change']);
        },
        listen(fn) {
          el.addEventListener('input', fn);
          el.addEventListener('change', fn);
          el.addEventListener('click', fn);
        },
      });
      return;
    }
    console.warn(`[toolSession] element for field "${name}" is not an input/textarea/select/radiogroup; skipping`);
  });

  return out;
}

export function persistToolSession(config: ToolSessionConfig): ToolSessionHandle {
  const noop = { save() {}, reset() {} };
  if (!config || !config.root) return noop;

  const root = config.root;
  // Idempotent init guard (same shape as animatedDetails.ts/animatedSwitch.ts's
  // own `__animatedDetails`/`__animatedSwitch` flags) — a tool script that
  // accidentally calls this twice on the same root (e.g. an HMR re-run in
  // dev) gets back the same handle instead of a second set of duplicate
  // listeners and a second debounce timer racing the first.
  if (root.__toolSession) return root.__toolSession;

  const STORAGE_KEY = 'toolsession:' + location.pathname;
  const debounceMs = typeof config.debounceMs === 'number' ? config.debounceMs : 400;
  const fields = bindFields(root);

  let saveTimer = null;
  let hydrating = false;
  let resetting = false;

  function readStored() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function doSave() {
    try {
      const blob = { fields: {} };
      fields.forEach((f) => {
        blob.fields[f.name] = f.get();
      });
      if (typeof config.serialize === 'function') {
        try {
          blob.extra = config.serialize();
        } catch (e) {
          /* ignore — a broken serialize() shouldn't lose the plain fields */
        }
      }
      localStorage.setItem(STORAGE_KEY, JSON.stringify(blob));
    } catch (e) {
      /* ignore */
    }
  }

  function scheduleSave() {
    if (hydrating || resetting) return;
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(doSave, debounceMs);
  }

  function doReset() {
    if (saveTimer) {
      clearTimeout(saveTimer);
      saveTimer = null;
    }
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (e) {
      /* ignore */
    }
    // Held for the whole reset pass (mirrors `hydrating`) so the
    // input/change events each f.reset()/onReset() dispatches don't
    // re-trigger scheduleSave() and silently resurrect the just-removed
    // key ~debounceMs later with the (default) values — the storage key
    // must stay genuinely removed after a reset, per this file's own
    // documented "removeItem, not an empty write" contract above.
    resetting = true;
    fields.forEach((f) => {
      try {
        f.reset();
      } catch (e) {
        /* ignore — one broken field shouldn't stop the rest from resetting */
      }
    });
    if (typeof config.onReset === 'function') {
      try {
        config.onReset();
      } catch (e) {
        /* ignore */
      }
    }
    resetting = false;
  }

  fields.forEach((f) => f.listen(scheduleSave));

  if (config.resetButton) {
    const btn = root.querySelector(config.resetButton);
    if (btn) btn.addEventListener('click', doReset);
  }

  const stored = readStored();
  if (stored) {
    hydrating = true;
    const storedFields = stored.fields && typeof stored.fields === 'object' ? stored.fields : {};
    fields.forEach((f) => {
      if (Object.prototype.hasOwnProperty.call(storedFields, f.name)) {
        try {
          f.apply(storedFields[f.name]);
        } catch (e) {
          /* ignore — one bad stored value shouldn't block the rest */
        }
      }
    });
    hydrating = false;
    if (typeof config.restore === 'function') {
      try {
        config.restore(stored.extra);
      } catch (e) {
        /* ignore */
      }
    }
  }

  const handle = {
    save() {
      if (saveTimer) {
        clearTimeout(saveTimer);
        saveTimer = null;
      }
      doSave();
    },
    reset: doReset,
  };
  root.__toolSession = handle;
  return handle;
}
