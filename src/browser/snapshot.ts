/**
 * Page-state extraction. The scripts run inside the page as plain strings, so no
 * build-time helper can leak into them, and they only read the DOM: they never
 * set attributes, add listeners or keep state the page could observe later.
 *
 * Everything returned here is untrusted page content. Element names come from
 * labels and visible text, never from form-field values, and are length-bounded.
 */

export interface ElementInfo {
  /** 1-based; valid until the next snapshot. */
  index: number;
  tag: string;
  role: string | null;
  /** input type, lower case; null for other elements. */
  type: string | null;
  name: string;
  /** Link target as UrlDisclosure allows (origin unless opted in); null if not a link. */
  href: string | null;
  disabled: boolean;
  in_viewport: boolean;
  editable: boolean;
  /** Activating it would submit a form (submit button or image input inside a form). */
  submits_form: boolean;
}

/** Raw element data from the page, before the href is disclosed and the index assigned. */
export interface RawElement {
  tag: string;
  role: string | null;
  type: string | null;
  name: string;
  href: string | null;
  disabled: boolean;
  in_viewport: boolean;
  editable: boolean;
  submits_form: boolean;
}

export interface RawPageState {
  title: string;
  text: string;
  text_truncated: boolean;
  elements_truncated: boolean;
}

export const INTERACTIVE_SELECTOR = [
  "a[href]",
  "button",
  "input",
  "select",
  "textarea",
  "summary",
  "[contenteditable='']",
  "[contenteditable='true']",
  "[onclick]",
  "[tabindex]:not([tabindex='-1'])",
  ...["button", "link", "checkbox", "radio", "tab", "menuitem", "option", "switch", "textbox", "combobox", "searchbox"].map((r) => `[role='${r}']`),
].join(", ");

/**
 * Returns { state, items, elements }: `elements` stays in the page and is read
 * back as element handles, in the same order as `items`.
 */
export function snapshotScript(maxElements: number, maxTextChars: number, maxNameChars: number): string {
  return `(() => {
  const SELECTOR = ${JSON.stringify(INTERACTIVE_SELECTOR)};
  const MAX_ELEMENTS = ${maxElements};
  const MAX_TEXT = ${maxTextChars};
  const MAX_NAME = ${maxNameChars};
  const clip = (s) => {
    const t = String(s || "").replace(/\\s+/g, " ").trim();
    return t.length > MAX_NAME ? t.slice(0, MAX_NAME) + "\\u2026" : t;
  };
  const vw = window.innerWidth, vh = window.innerHeight;
  const items = [];
  const elements = [];
  let truncated = false;
  for (const el of document.querySelectorAll(SELECTOR)) {
    if (!(el instanceof HTMLElement)) continue;
    const tag = el.tagName.toLowerCase();
    const type = tag === "input" ? (el.getAttribute("type") || "text").toLowerCase() : null;
    if (type === "hidden") continue;
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    if ((rect.width === 0 && rect.height === 0) || style.visibility === "hidden" || style.display === "none") continue;
    if (items.length >= MAX_ELEMENTS) { truncated = true; break; }
    let name = el.getAttribute("aria-label") || "";
    if (!name) {
      const ids = (el.getAttribute("aria-labelledby") || "").split(/\\s+/).filter(Boolean);
      name = ids.map((id) => (document.getElementById(id) || {}).innerText || "").join(" ");
    }
    if (!name && el.labels && el.labels.length) name = Array.from(el.labels).map((l) => l.innerText).join(" ");
    // Never a field's value: it may hold what the user typed or a prefilled secret.
    if (!name && tag !== "input" && tag !== "textarea" && tag !== "select") name = el.innerText;
    if (!name && (type === "submit" || type === "button" || type === "reset")) name = el.getAttribute("value") || type;
    if (!name) name = el.getAttribute("alt") || el.getAttribute("title") || el.getAttribute("placeholder") || "";
    const form = el.form || null;
    const submits =
      !!form &&
      ((tag === "button" && (el.getAttribute("type") || "submit").toLowerCase() === "submit") || type === "submit" || type === "image");
    items.push({
      tag,
      role: el.getAttribute("role"),
      type,
      name: clip(name),
      href: tag === "a" && el.href ? String(el.href) : null,
      disabled: !!el.disabled || el.getAttribute("aria-disabled") === "true",
      in_viewport: rect.bottom > 0 && rect.right > 0 && rect.top < vh && rect.left < vw,
      editable: el.isContentEditable || tag === "textarea" || (tag === "input" && !["button", "submit", "reset", "image", "checkbox", "radio", "file", "range", "color"].includes(type)),
      submits_form: submits,
    });
    elements.push(el);
  }
  const body = document.body ? document.body.innerText || "" : "";
  const state = {
    title: document.title || "",
    text: body.length > MAX_TEXT ? body.slice(0, MAX_TEXT) : body,
    text_truncated: body.length > MAX_TEXT,
    elements_truncated: truncated,
  };
  return { state, items, elements };
})()`;
}

export interface ElementGuard {
  connected: boolean;
  tag: string;
  type: string | null;
  autocomplete: string;
  submits_form: boolean;
  editable: boolean;
  disabled: boolean;
}

/**
 * Re-reads an element's facts at action time; the snapshot may be stale. Built
 * with the Function constructor from a string so it is sent to the page as written.
 */
export const elementGuard = new Function(
  "el",
  `const tag = el.tagName ? el.tagName.toLowerCase() : "";
  const type = tag === "input" ? (el.getAttribute("type") || "text").toLowerCase() : null;
  const form = el.form || null;
  return {
    connected: !!el.isConnected,
    tag,
    type,
    autocomplete: ((el.getAttribute && el.getAttribute("autocomplete")) || "").toLowerCase(),
    submits_form: !!form && ((tag === "button" && (el.getAttribute("type") || "submit").toLowerCase() === "submit") || type === "submit" || type === "image"),
    editable: !!el.isContentEditable || tag === "textarea" || (tag === "input" && !["button", "submit", "reset", "image", "checkbox", "radio", "file", "range", "color", "hidden"].includes(type)),
    disabled: !!el.disabled,
  };`,
) as (el: Element) => ElementGuard;
