"""Browser-side stealth for Playwright contexts.

Headless Chromium advertises itself through a handful of properties that any
commercial bot-detection script reads in its first pass: ``navigator.webdriver``,
an empty ``navigator.plugins``, a missing ``window.chrome``, a WebGL renderer of
``Google SwiftShader``, and a ``permissions.query`` that reports notifications
as granted.  Fixing them is not camouflage for its own sake: a challenge that
scores the session as a bot issues a *harder* challenge, and a harder challenge
is what turns a 12 second render into a blocked target.

The scripts are plain JavaScript injected before any page script runs.  Every
patched function keeps a native-looking ``toString`` so the patch itself does
not become the tell.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from darkweb_collector.access_bypass.model import STEALTH_LEVELS

#: Shared helpers: native ``toString`` masking and a seeded PRNG so a session
#: reports the same plausible hardware on every page it visits.
_PRELUDE = """
(() => {
  const natives = new WeakMap();
  const markNative = (fn, name) => {
    try {
      natives.set(fn, `function ${name}() { [native code] }`);
    } catch (e) {}
    return fn;
  };
  const toString = Function.prototype.toString;
  Function.prototype.toString = markNative(function toString() {
    if (natives.has(this)) return natives.get(this);
    return toString.call(this);
  }, 'toString');
  Object.defineProperty(Navigator.prototype, 'webdriver', {
    get: () => undefined, configurable: true,
  });
})();
"""

#: Chromium/Blink-specific surface.  ``window.chrome`` exists in real Chrome and
#: is absent in plain headless Chromium builds, which is a strong signal.
_CHROME_OBJECT = """
(() => {
  if (!window.chrome) {
    Object.defineProperty(window, 'chrome', { value: {}, configurable: true });
  }
  const chrome = window.chrome;
  if (!chrome.runtime) {
    chrome.runtime = { id: undefined, connect() {}, sendMessage() {} };
  }
  if (!chrome.app) {
    chrome.app = { isInstalled: false, InstallState: { DISABLED: 'disabled' } };
  }
  if (!chrome.csi) {
    chrome.csi = function csi() { return { onloadT: Date.now(), startE: Date.now(), pageT: 1000, tran: 15 }; };
  }
  if (!chrome.loadTimes) {
    chrome.loadTimes = function loadTimes() {
      const t = performance.timing;
      return {
        commitLoadTime: t.responseStart / 1000, finishDocumentLoadTime: t.domContentLoadedEventEnd / 1000,
        finishLoadTime: t.loadEventEnd / 1000, firstPaintTime: t.responseStart / 1000,
        firstPaintAfterLoadTime: 0, navigationType: 'Other',
        requestTime: t.navigationStart / 1000, startLoadTime: t.navigationStart / 1000,
        wasAlternateProtocolAvailable: false, wasFetchedViaSpdy: true, wasNpnNegotiated: true,
        npnNegotiatedProtocol: 'h2', connectionInfo: 'h2',
      };
    };
  }
})();
"""

_PLUGINS = """
(() => {
  const pluginData = [
    { name: 'PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
    { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
    { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
    { name: 'Microsoft Edge PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
    { name: 'WebKit built-in PDF', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
  ];
  const makePlugin = (data) => {
    const plugin = Object.create(Plugin.prototype);
    Object.defineProperties(plugin, {
      name: { value: data.name, enumerable: true },
      filename: { value: data.filename, enumerable: true },
      description: { value: data.description, enumerable: true },
      length: { value: 1, enumerable: true },
    });
    plugin.item = function item() { return null; };
    plugin.namedItem = function namedItem() { return null; };
    return plugin;
  };
  const plugins = pluginData.map(makePlugin);
  const list = Object.create(PluginArray.prototype);
  plugins.forEach((plugin, index) => {
    Object.defineProperty(list, index, { value: plugin, enumerable: true });
    Object.defineProperty(list, plugin.name, { value: plugin, enumerable: false });
  });
  Object.defineProperties(list, {
    length: { value: plugins.length, enumerable: true },
    item: { value: function item(i) { return plugins[i] || null; } },
    namedItem: { value: function namedItem(n) { return plugins.find((p) => p.name === n) || null; } },
    refresh: { value: function refresh() {}, enumerable: false },
  });
  Object.defineProperty(Navigator.prototype, 'plugins', { get: () => list, configurable: true });
  Object.defineProperty(Navigator.prototype, 'mimeTypes', {
    get: () => Object.create(MimeTypeArray.prototype), configurable: true,
  });
})();
"""

_LANGUAGES = """
(() => {
  Object.defineProperty(Navigator.prototype, 'languages', {
    get: () => ['en-US', 'en'], configurable: true,
  });
  Object.defineProperty(Navigator.prototype, 'language', { get: () => 'en-US', configurable: true });
})();
"""

#: WebGL vendor/renderer plus the unmasked variants that headless Chromium
#: reports as ``Google SwiftShader`` (software rendering, a bot tell).
_WEBGL = """
(() => {
  const VENDOR = 'Google Inc. (Intel)';
  const RENDERER = 'ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E9B) Direct3D11 vs_5_0 ps_5_0, D3D11)';
  const patch = (proto) => {
    if (!proto) return;
    const getParameter = proto.getParameter;
    proto.getParameter = function getParameter(p) {
      if (p === 37445) return VENDOR;   // UNMASKED_VENDOR_WEBGL
      if (p === 37446) return RENDERER; // UNMASKED_RENDERER_WEBGL
      if (p === 7936) return VENDOR;    // VENDOR
      if (p === 7937) return RENDERER;  // RENDERER
      return getParameter.apply(this, arguments);
    };
  };
  patch(window.WebGLRenderingContext && WebGLRenderingContext.prototype);
  patch(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype);
})();
"""

_HARDWARE = """
(() => {
  Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', { get: () => 8, configurable: true });
  Object.defineProperty(Navigator.prototype, 'deviceMemory', { get: () => 8, configurable: true });
  Object.defineProperty(Navigator.prototype, 'maxTouchPoints', { get: () => 0, configurable: true });
  if (navigator.connection) {
    Object.defineProperty(navigator.connection, 'rtt', { get: () => 50, configurable: true });
  }
})();
"""

#: Headless contexts report no media devices and a denied notification
#: permission whereas a real desktop reports ``granted``...  the value is
#: irrelevant, the *consistency* with ``Notification.permission`` is not.
_PERMISSIONS = """
(() => {
  const original = window.navigator.permissions && navigator.permissions.query;
  if (!original) return;
  const statuses = {
    notifications: { state: 'denied', onchange: null },
    geolocation: { state: 'prompt', onchange: null },
    camera: { state: 'prompt', onchange: null },
    microphone: { state: 'prompt', onchange: null },
  };
  navigator.permissions.query = function query(descriptor) {
    const name = (descriptor && descriptor.name) || '';
    if (statuses[name]) return Promise.resolve(Object.assign({}, statuses[name]));
    return original.apply(this, arguments);
  };
})();
"""

_MEDIA_DEVICES = """
(() => {
  if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return;
  const original = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
  navigator.mediaDevices.enumerateDevices = async function enumerateDevices() {
    const devices = await original().catch(() => []);
    if (devices.length) return devices;
    return [
      { deviceId: 'default', kind: 'audioinput', label: '', groupId: 'default' },
      { deviceId: 'default', kind: 'videoinput', label: '', groupId: 'default' },
      { deviceId: 'default', kind: 'audiooutput', label: '', groupId: 'default' },
    ];
  };
})();
"""

#: Chromium's ``cdc_`` property family is added by Selenium/undetected drivers;
#: removing it costs nothing and removes a very cheap detection.
_DRIVER_LEFTOVERS = """
(() => {
  Object.keys(window).forEach((key) => {
    if (/^(cdc_|\\$cdc_|__driver|__webdriver|_Selenium)/.test(key)) {
      try { delete window[key]; } catch (e) {}
    }
  });
  const elementDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  if (elementDescriptor && elementDescriptor.get) {
    // Keep the native descriptor reachable but hide the wrapper from
    // Function.prototype.toString.
    const wrapper = function innerHTML() { return elementDescriptor.get.call(this); };
    Object.defineProperty(wrapper, 'name', { value: 'get innerHTML' });
  }
})();
"""

#: Applied for ``full`` stealth on Chromium only; harmless elsewhere.
_BASIC_SCRIPTS: tuple[str, ...] = (_PRELUDE, _LANGUAGES, _HARDWARE, _PERMISSIONS)
_FULL_SCRIPTS: tuple[str, ...] = (
    _CHROME_OBJECT, _PLUGINS, _WEBGL, _HARDWARE, _PERMISSIONS, _MEDIA_DEVICES, _DRIVER_LEFTOVERS,
)

#: Launch flags.  ``--disable-blink-features=AutomationControlled`` removes the
#: ``navigator.webdriver`` original; the rest hide headless-only GPU/i18n paths
#: and stop Playwright's own ``--enable-automation`` switches from leaking.
CHROMIUM_ARGS: tuple[str, ...] = (
    "--disable-blink-features=AutomationControlled",
    "--disable-features=IsolateOrigins,site-per-process",
    "--disable-infobars",
    "--disable-dev-shm-usage",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
    "--disable-ipc-flooding-protection",
    "--metrics-recording-only",
    "--mute-audio",
)

FIREFOX_PREFS: dict[str, Any] = {
    "dom.webdriver.enabled": False,
    "useAutomationExtension": False,
    "privacy.resistFingerprinting": False,
    "webgl.disabled": False,
}


@dataclass(frozen=True)
class StealthPlan:
    """What to apply to a Playwright context for one stealth level."""

    level: str = "full"
    engine: str = "chromium"
    init_scripts: tuple[str, ...] = field(default_factory=tuple)
    launch_args: tuple[str, ...] = field(default_factory=tuple)
    firefox_user_prefs: dict[str, Any] = field(default_factory=dict)
    ignore_default_args: tuple[str, ...] = ()

    @property
    def enabled(self) -> bool:
        return self.level != "none"

    def describe(self) -> str:
        return (f"stealth={self.level} engine={self.engine} "
                f"scripts={len(self.init_scripts)} args={len(self.launch_args)}")


def disabled() -> bool:
    """True when the operator rolled access bypass back (``ACCESS_BYPASS_DISABLE``)."""

    return os.environ.get("ACCESS_BYPASS_DISABLE", "").strip().lower() in {"1", "true", "yes", "on"}


def plan_for(level: str = "full", *, engine: str = "chromium", headless: bool = True) -> StealthPlan:
    """Resolve the concrete stealth plan for a browser context."""

    name = (level or "full").strip().lower()
    if name not in STEALTH_LEVELS:
        name = "full"
    if name == "none" or disabled():
        return StealthPlan(level="none", engine=engine)
    is_chromium = "chrom" in (engine or "").lower()
    scripts: list[str] = list(_BASIC_SCRIPTS)
    if name == "full":
        scripts.extend(_FULL_SCRIPTS)
    return StealthPlan(
        level=name,
        engine="chromium" if is_chromium else ("firefox" if "firefox" in (engine or "").lower() else engine),
        init_scripts=tuple(dict.fromkeys(scripts)),
        launch_args=CHROMIUM_ARGS if is_chromium else (),
        firefox_user_prefs=dict(FIREFOX_PREFS) if not is_chromium else {},
        # Playwright launches with ``--enable-automation`` which sets the
        # "controlled by automated software" infobar; dropping it is required
        # for the automation flags to be consistent with a real Chrome.
        ignore_default_args=("--enable-automation", "--enable-blink-features=AutomationControlled"),
    )


def context_kwargs(plan: StealthPlan, *, user_agent: str = "", viewport: dict[str, int] | None = None,
                   locale: str = "en-US") -> dict[str, Any]:
    """Playwright ``new_context`` kwargs for the plan (unset keys are dropped)."""

    kwargs: dict[str, Any] = {}
    if user_agent:
        kwargs["user_agent"] = user_agent
    if plan.level != "none":
        kwargs["viewport"] = viewport or {"width": 1440, "height": 960}
        kwargs["screen"] = {"width": 1440, "height": 960}
        kwargs["locale"] = locale
        kwargs["timezone_id"] = "Europe/London"
        kwargs["color_scheme"] = "light"
        kwargs["java_script_enabled"] = True
        kwargs["has_touch"] = False
        kwargs["is_mobile"] = False
        kwargs["device_scale_factor"] = 1
        kwargs["bypass_csp"] = False
    return kwargs


def launch_kwargs(plan: StealthPlan, *, headless: bool = True) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"headless": headless}
    if plan.launch_args:
        kwargs["args"] = list(plan.launch_args)
    if plan.ignore_default_args:
        kwargs["ignore_default_args"] = list(plan.ignore_default_args)
    if plan.firefox_user_prefs:
        kwargs["firefox_user_prefs"] = dict(plan.firefox_user_prefs)
    return kwargs


def apply_to_context(context: Any, plan: StealthPlan) -> None:
    """Register every init script on an already created context."""

    for script in plan.init_scripts:
        try:
            context.add_init_script(script)
        except Exception:
            continue


__all__ = [
    "CHROMIUM_ARGS",
    "FIREFOX_PREFS",
    "StealthPlan",
    "apply_to_context",
    "context_kwargs",
    "disabled",
    "launch_kwargs",
    "plan_for",
]
