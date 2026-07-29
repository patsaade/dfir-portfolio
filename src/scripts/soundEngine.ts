// @ts-nocheck — vanilla DOM client utility
// The Web Audio half of the opt-in interface-sound feature. Split out of
// SoundEngine.astro into its own module so it can be `import()`ed LAZILY:
// sound is OFF by default, so on the overwhelming majority of page loads this
// code is never fetched at all. SoundEngine.astro keeps only a ~20-line loader
// eager (it reads the stored preference and, if it is already 'on', pulls this
// chunk in immediately); SoundToggle.astro pulls it in the first time a visitor
// switches sound on. Everything below is byte-for-byte the behaviour that used
// to live inline in SoundEngine.astro — only the packaging changed.
//
// Tiny Web Audio synth: no assets, no dependency — short oscillator "blips"
// generated on the fly. Exposes window.__sound, used by SoundToggle +
// HoverCards + Search (all of which already guard with `if (window.__sound)`,
// which is what makes late initialisation safe); a delegated listener voices
// the chrome the user clicks (buttons, copy actions, links — internal,
// external, and in-page anchors). Any element can opt into a cue declaratively
// with data-sound="tick|copy|card|nav|on".
//
// Mobile hardening: the AudioContext is created lazily inside a gesture, and is
// unlocked/resumed on the first touch and whenever the tab becomes visible again
// (mobile browsers suspend backgrounded contexts — the classic "sound stops after
// you switch apps" bug). Per the user's choice, there's no haptic/vibration.

/**
 * Define window.__sound and install the delegated cue listeners. Idempotent —
 * a second call is a no-op, so the loader and the toggle can both request it
 * without coordinating.
 */
export function initSound() {
  if (window.__sound) return;
  var KEY = 'sound';
  var enabled = false;
  try { enabled = localStorage.getItem(KEY) === 'on'; } catch (e) {}

  var ctx = null;
  function ensureCtx() {
    if (ctx) return ctx;
    var AC = window.AudioContext || window['webkitAudioContext'];
    if (!AC) return null;
    try { ctx = new AC(); } catch (e) { ctx = null; }
    return ctx;
  }
  // Create (if needed) and resume the context. Safe to call repeatedly; only
  // does real work inside/after a user gesture, which is where it's invoked.
  function unlock() {
    var c = ensureCtx();
    if (c && c.state === 'suspended' && c.resume) { try { c.resume(); } catch (e) {} }
    return c;
  }

  // Schedule one short, soft blip on a *running* context. Low gain + fast decay
  // keep it a tick, not a beep. Every Web Audio call is wrapped: an audio hiccup
  // (bad/closed context, node limit, ramp edge case) must never surface as an
  // error or break the click.
  function schedule(o, c) {
    try {
      var t = c.currentTime;
      var dur = o.dur || 0.07;
      var osc = c.createOscillator();
      var gain = c.createGain();
      osc.type = o.type || 'sine';
      osc.frequency.setValueAtTime(o.freq || 600, t);
      if (o.freq2) osc.frequency.exponentialRampToValueAtTime(o.freq2, t + dur);
      gain.gain.setValueAtTime(0.0001, t);
      gain.gain.exponentialRampToValueAtTime(o.vol || 0.05, t + 0.005);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + dur);
      osc.connect(gain);
      gain.connect(c.destination);
      osc.start(t);
      osc.stop(t + dur + 0.02);
    } catch (e) {
      /* swallow — sound is a non-essential enhancement */
    }
  }
  // Play a cue. If the context is still suspended — the first interaction on a
  // freshly loaded page, the classic "first click is silent" case — resume FIRST
  // and play once it's actually running, so even the very first cue is audible.
  // This is also what keeps the very first cue after ENABLING audible now that
  // this module arrives via a dynamic import: `set(true)` runs a tick or two
  // after the toggle's click, so the context may well still be suspended.
  function blip(o) {
    if (!enabled || !o) return;
    var c = ensureCtx();
    if (!c) return;
    if (c.state === 'suspended' && c.resume) {
      c.resume().then(function () { schedule(o, c); }, function () {});
    } else {
      schedule(o, c);
    }
  }

  // Soft-blip palette: one distinguishable cue per interaction class. `vol` is
  // the peak gain (linear amplitude, 0–1). UI feedback conventionally sits around
  // -18…-13 dBFS peak (amplitude = 10^(dB/20): -18≈0.13, -15≈0.18, -13≈0.22);
  // pure tones read louder than samples, so these stay at the conservative end
  // and keep their relative balance — `card` faintest, the `on` chirp loudest.
  var SOUNDS = {
    tick: { freq: 520, freq2: 700, type: 'triangle', dur: 0.05, vol: 0.14 }, // UI controls
    copy: { freq: 720, freq2: 1080, type: 'triangle', dur: 0.08, vol: 0.16 }, // copy code
    card: { freq: 660, freq2: 840, type: 'sine', dur: 0.045, vol: 0.12 }, // context card / term
    nav: { freq: 600, freq2: 460, type: 'sine', dur: 0.08, vol: 0.15 }, // page navigation
    on: { freq: 480, freq2: 900, type: 'sine', dur: 0.13, vol: 0.2 }, // enable confirmation
  };

  window.__sound = {
    isEnabled: function () { return enabled; },
    play: function (name) { try { blip(SOUNDS[name] || SOUNDS.tick); } catch (e) {} },
    set: function (on) {
      enabled = !!on;
      try { localStorage.setItem(KEY, enabled ? 'on' : 'off'); } catch (e) {}
      try { document.dispatchEvent(new CustomEvent('soundchange')); } catch (e) {}
      // The toggle click is a user gesture, so this confirming chirp is allowed.
      if (enabled) { unlock(); blip(SOUNDS.on); }
    },
    toggle: function () { this.set(!enabled); },
  };

  // Resume after the tab/app regains focus (mobile suspends the context).
  document.addEventListener('visibilitychange', function () {
    if (enabled && !document.hidden) unlock();
  });

  // Resolve the cue for a target (null = none). Resolution order:
  //   1. data-sound="<cue>" — declarative opt-in; the value names the cue, so a
  //      new cued control needs no edit here. (data-sound-toggle is NOT matched.)
  //   2. .copy-btn → copy
  //   3. <a href="#…"> in-page anchor (ToC, skip-link, back-to-top) → tick; any
  //      other real link, internal OR external → nav;
  //      mailto:/tel:/javascript:/download → none.
  //   4. any other <button> → tick (sound toggle + search trigger voice their own)
  function cueFor(t) {
    if (!t || !t.closest) return null;
    var explicit = t.closest('[data-sound]');
    if (explicit) return explicit.getAttribute('data-sound') || 'tick';
    if (t.closest('.copy-btn')) return 'copy';
    var link = t.closest('a[href]');
    if (link) {
      var href = link.getAttribute('href') || '';
      if (href[0] === '#') return 'tick';
      if (!link.hasAttribute('download') && !/^(mailto:|tel:|javascript:)/i.test(href)) return 'nav';
      return null;
    }
    if (t.closest('button') && !t.closest('[data-sound-toggle]') && !t.closest('[data-search-trigger]')) return 'tick';
    return null;
  }
  function fire(e) {
    if (!enabled) return;
    try { var cue = cueFor(e.target); if (cue) window.__sound.play(cue); } catch (err) {}
  }

  // Voice cues on POINTERDOWN, not click. A navigation link tears the page down on
  // click, which cut the blip off before it was audible — the reported bug ("no
  // sound until you click on the new page"). Firing on press gives the tone time
  // to play before navigation, and unlocks the context early so the first cue on a
  // fresh page isn't swallowed. Capture phase so a stopPropagation handler can't
  // mute it; this also primes audio on any first touch (the iOS/Android case).
  var lastPd = 0;
  document.addEventListener('pointerdown', function (e) {
    if (!enabled) return;
    unlock();
    lastPd = e.timeStamp;
    fire(e);
  }, true);
  // Keyboard activation (Enter/Space) emits a click with no preceding pointerdown
  // (detail === 0); voice those here. Mouse/touch already fired on pointerdown.
  document.addEventListener('click', function (e) {
    if (e.detail === 0 && e.timeStamp - lastPd > 700) fire(e);
  }, true);
}
