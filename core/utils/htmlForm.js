'use strict';

/**
 * Lightweight, dependency-free extraction of a login <form>'s fields from raw HTML. Not a
 * full HTML parser - good enough for the server-rendered <form>/<input> markup essentially
 * every classic login page uses (DVWA, WordPress, Django admin, etc.), which is exactly the
 * class of app that needs this (JS-rendered SPA logins are handled by jsonLogin instead,
 * which talks to the API directly and never touches HTML).
 *
 * Exists so a user only ever has to supply a login URL + credentials - CSRF tokens, submit-
 * button fields, and field names are discovered from the page itself, not hand-configured.
 */

/** Extracts attribute="value" pairs from a single <input .../> tag string. */
function parseAttributes(tag) {
  const attrs = {};
  const re = /([a-zA-Z-]+)\s*=\s*("([^"]*)"|'([^']*)')/g;
  let m;
  while ((m = re.exec(tag))) {
    attrs[m[1].toLowerCase()] = m[3] !== undefined ? m[3] : m[4];
  }
  return attrs;
}

/**
 * Finds the <form> most likely to be the login form (the first one containing a
 * type="password" input) and returns its action URL and field list.
 * @returns {{action: string|null, fields: Array<{name:string,type:string,value:string}>}|null}
 */
function extractLoginForm(html) {
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let match;
  while ((match = formRe.exec(html))) {
    const [, formAttrsStr, body] = match;
    const inputRe = /<input\b[^>]*>/gi;
    const inputs = body.match(inputRe) || [];
    const fields = inputs
      .map((tag) => parseAttributes(tag))
      .filter((attrs) => attrs.name)
      .map((attrs) => ({
        name: attrs.name,
        type: (attrs.type || 'text').toLowerCase(),
        value: attrs.value || ''
      }));

    if (fields.some((f) => f.type === 'password')) {
      const formAttrs = parseAttributes(`<form ${formAttrsStr}>`);
      return { action: formAttrs.action || null, fields };
    }
  }
  return null;
}

/**
 * Builds a login POST body from the detected form fields, filling in the real
 * username/password and preserving everything else (hidden CSRF tokens, submit-button
 * name/value pairs) verbatim.
 * @param {ReturnType<typeof extractLoginForm>} form
 * @param {{username: string, password: string, usernameField?: string, passwordField?: string}} creds
 * @returns {URLSearchParams}
 */
function buildLoginBody(form, { username, password, usernameField, passwordField }) {
  const body = new URLSearchParams();
  let usernameSet = false;

  for (const field of form.fields) {
    if (field.type === 'password' || (passwordField && field.name === passwordField)) {
      body.set(field.name, password);
      continue;
    }
    const looksLikeUsername =
      (usernameField && field.name === usernameField) ||
      (!usernameField &&
        !usernameSet &&
        ['text', 'email'].includes(field.type) &&
        /user|email|login|name/i.test(field.name));
    if (looksLikeUsername) {
      body.set(field.name, username);
      usernameSet = true;
      continue;
    }
    if (field.type === 'checkbox' || field.type === 'radio') {
      continue; // skip unchecked-by-default boxes/radios - most login forms don't need them
    }
    // Hidden fields (CSRF tokens), submit buttons, and anything else: keep as-is.
    body.set(field.name, field.value);
  }

  // Fallback: no field looked like a username (e.g. unusual naming) - use the explicit
  // field name if given, else the first non-password, non-hidden, non-submit field.
  if (!usernameSet) {
    const fallback =
      (usernameField && form.fields.find((f) => f.name === usernameField)) ||
      form.fields.find((f) => !['password', 'hidden', 'submit'].includes(f.type));
    if (fallback) body.set(fallback.name, username);
  }

  return body;
}

module.exports = { extractLoginForm, buildLoginBody };
