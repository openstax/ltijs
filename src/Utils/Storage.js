/* Storage service - implements the LTI OIDC Client Side postMessage storage handshake */
/* https://www.imsglobal.org/spec/lti-cs-oidc/v0p1 */

const path = require('path')
const { sprightly } = require('sprightly')
const jwt = require('jsonwebtoken')

const putTemplatePath = path.join(__dirname, '../Templates', 'OidcStoragePut.html')
const getTemplatePath = path.join(__dirname, '../Templates', 'OidcStorageGet.html')

const STORAGE_KEY_PREFIX = 'ltijs'
const STORAGE_VALUE_TTL = '10m'
const STORAGE_VALUE_TYP = 'ltijs-storage-iss'

const FRAME_NAME_RE = /^[\w.-]{1,64}$/
const FRAME_NAME_BLOCKLIST = new Set([
  'opener', 'top', 'parent', 'self', 'location', 'frames', 'window', 'constructor', '__proto__', 'prototype'
])

class Storage {
  /**
   * @description Builds the platform-storage key for a given state. Always derived server-side from an
   * already-validated state, never accepted as request input - this is what binds the stored value to one
   * specific login attempt.
   */
  static buildKey (state) {
    return STORAGE_KEY_PREFIX + '_state_' + state
  }

  /**
   * @description State is always server-generated (crypto.randomBytes(25).toString('hex')), never platform-
   * or client-supplied in any legitimate flow - so this rejects anything that isn't a plain, URL-safe token
   * string. The typeof check is what actually closes the NoSQL-injection risk (rejecting any object); the
   * character check is a sanity backstop, not narrowed to hex specifically.
   */
  static sanitizeState (rawState) {
    return typeof rawState === 'string' && /^[\w-]+$/.test(rawState) ? rawState : undefined
  }

  /**
   * @description lti_storage_target is an unauthenticated query param on the login endpoint - never trust it
   * raw. Falls back to '_parent' if the value doesn't look like a safe frame name.
   */
  static sanitizeFrameName (frameName) {
    if (typeof frameName === 'string' && FRAME_NAME_RE.test(frameName) && !FRAME_NAME_BLOCKLIST.has(frameName)) return frameName
    return '_parent'
  }

  /**
   * @description Canvas changed its OIDC endpoints to https://sso.canvaslms.com but old records might still have https://canvas.instructure.com
   */
  static mapStorageOrigin (origin) {
    return typeof origin === 'string'
      ? origin.replace(/^https:\/\/canvas(\.[^.]+)?\.instructure\.com$/, 'https://sso$1.canvaslms.com')
      : origin
  }

  /**
   * @description Signs the iss value (plus the binding state and a discriminating typ) for storage on the
   * platform side, mirroring the trust the state cookie provides today.
   */
  static signValue (iss, state, ENCRYPTIONKEY) {
    return jwt.sign({ iss, state, typ: STORAGE_VALUE_TYP }, ENCRYPTIONKEY, { expiresIn: STORAGE_VALUE_TTL, algorithm: 'HS256' })
  }

  /**
   * @description Verifies a value recovered from platform storage. Returns undefined on any failure
   * (expired/tampered/malformed/wrong-typ/state-mismatch) so callers can treat it exactly like a missing cookie.
   */
  static verifyValue (value, state, ENCRYPTIONKEY) {
    if (typeof value !== 'string' || !value) return undefined
    try {
      const payload = jwt.verify(value, ENCRYPTIONKEY, { algorithms: ['HS256'] })
      if (payload.typ !== STORAGE_VALUE_TYP) return undefined
      if (payload.state !== state) return undefined
      return payload.iss
    } catch (err) {
      return undefined
    }
  }

  /**
   * @description Escapes a value for safe interpolation inside a <script> block. JSON.stringify handles the
   * JS-string-literal escaping; the extra </g, '<'> replace prevents a literal '</script' sequence
   * (which JSON.stringify does not escape) from breaking out of the enclosing <script> tag at the HTML-parser
   * level, regardless of JS syntax.
   */
  static toJs (value) {
    return JSON.stringify(value === undefined ? null : value).replace(/</g, '\\u003c')
  }

  /**
   * @description Escapes a value for safe interpolation inside an HTML attribute. Order matters - '&' must be
   * escaped first, or the other replacements would double-escape.
   */
  static toHtmlAttr (value) {
    return String(value === undefined ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
  }

  /**
   * @description Renders the login-time page that attempts to store the signed iss value via lti.put_data
   * before redirecting (client-side) to the platform's auth endpoint.
   */
  static renderPutPage ({ platformOrigin, frameName, key, value, putTimeoutMs, redirectUrl }) {
    return sprightly(putTemplatePath, {
      platformOriginJs: this.toJs(platformOrigin),
      frameNameJs: this.toJs(frameName),
      keyJs: this.toJs(key),
      valueJs: this.toJs(value),
      putTimeoutMsJs: this.toJs(putTimeoutMs),
      redirectUrlJs: this.toJs(redirectUrl)
    })
  }

  /**
   * @description Renders the callback-time recovery page that attempts to recover the signed iss value via
   * lti.get_data, then resubmits to the tool with the recovered value. id_token/state are still unvalidated
   * request input at this point - toHtmlAttr must be applied unconditionally, not skipped based on any
   * upstream validation.
   */
  static renderGetPage ({ platformOrigin, frameName, key, getTimeoutMs, idToken, state }) {
    return sprightly(getTemplatePath, {
      platformOriginJs: this.toJs(platformOrigin),
      frameNameJs: this.toJs(frameName),
      keyJs: this.toJs(key),
      getTimeoutMsJs: this.toJs(getTimeoutMs),
      idTokenAttr: this.toHtmlAttr(idToken),
      stateAttr: this.toHtmlAttr(state)
    })
  }
}

module.exports = Storage
