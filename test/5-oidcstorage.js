// Tests for the LTI Client Side postMessage storage handshake (LTI-CS-OIDC v0.1)
// and the related NoSQL-injection fixes found while implementing it

const jwt = require('jsonwebtoken')
const nock = require('nock')
const cheerio = require('cheerio')

const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)

const expect = chai.expect

const ENCRYPTIONKEY = 'LTIKEY'
const ISS = 'http://localhost/moodle'
const CLIENT_ID = 'ClientId1'
const KID = '123456'
const PLATFORM_ORIGIN = 'http://localhost'
const SIGNED_ISS_COOKIE_VALUE = 's%3Ahttp%3A%2F%2Flocalhost%2Fmoodle.fsJogjTuxtbJwvJcuG4esveQAlih67sfEltuwRM6MX0'
// Signed session cookie for platformCode('http://localhost/moodle' + 'ClientId1' + '2') / sub '2' - matches
// tokenValid's iss/aud/deployment_id/sub below, needed on the auto-followed ltik request after a successful launch
const SIGNED_SESSION_COOKIE = 'ltiaHR0cDovL2xvY2FsaG9zdC9tb29kbGVDbGllbnRJZDEy=s%3A2.ZezwPKtv3Uibp4A%2F6cN0UzbIQlhA%2BTAKvbtN%2FvgGaCI; Path=/; HttpOnly; SameSite=None'

const randomState = () => encodeURIComponent([...Array(25)].map(_ => (Math.random() * 36 | 0).toString(36)).join``)

// Valid complete token
const tokenValid = {
  exp: Math.floor(Date.now() / 1000) + (60 * 60),
  iss: ISS,
  aud: CLIENT_ID,
  'https://purl.imsglobal.org/spec/lti/claim/deployment_id': '2',
  'https://purl.imsglobal.org/spec/lti/claim/target_link_uri': 'https://localhost',
  sub: '2',
  'https://purl.imsglobal.org/spec/lti/claim/lis': { person_sourcedid: '', course_section_sourcedid: '' },
  'https://purl.imsglobal.org/spec/lti/claim/roles': [
    'http://purl.imsglobal.org/vocab/lis/v2/institution/person#Administrator'
  ],
  'https://purl.imsglobal.org/spec/lti/claim/context': { id: '3', label: 'Curso Teste', title: 'Curso Teste', type: [] },
  'https://purl.imsglobal.org/spec/lti/claim/resource_link': { title: 'teste local', id: '5' },
  'https://purl.imsglobal.org/spec/lti/claim/version': '1.3.0',
  'https://purl.imsglobal.org/spec/lti/claim/message_type': 'LtiResourceLinkRequest'
}

const signToken = (token, kid) => {
  const key = '-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIICWgIBAAKBgFayUq/sZYvDX7gHZP1npuQQEZpluAaSb1wcdzGxWP9IKx/Qnezs\n' +
  'QcFWEsCOD+MoS9u7qWtfxQkcC4t62jj0iTpBxA7xcLcmGTL3WHKQ2E7+iUVam4BM\n' +
  'mbR2vr4y9cAaqlu+cjw0aMmXZwPDFq38kVDmpOd2VVh0SoAZz+d6F5uzAgMBAAEC\n' +
  'gYA8ZDOdQHrsBMiklOIQcyeaLmdUug6a5V6VN28AOp3YFhmUK+oWo+yaFK8zWsJO\n' +
  'Zj+RbQPzO98xHUwdeRKSIiWEk0MT0Y7GfOL61dRNoZty9v/Sf88xTm6djPMZg+LU\n' +
  'npQmBgKtjSBFWJAy0NMn3U892lr6iFfYe5OAMg6ARV6RQQJBAJ/KG2Ds4ig0dURH\n' +
  'UK6Smt76uCtI6HGsSSn58sz5kWmfytfsqj0DHA9ZQrJj/WXa6ex6FL4YIgZBtv/T\n' +
  'UZi/zikCQQCK5bOoAfVzYGb6d94LC4P5OtUN77xF92xbRxRwHyvVwXve9W8Qx0Jl\n' +
  '/tdgvds6AxMZszIqX/mw7B7eA8AM6N57AkBI1wXiCjoSH8+xH11NJzGIIfygZqzn\n' +
  'XKVBiFpBTCcYYipCgfUcuPUqngMEdQZHTyLBlOktuqyP85brSbZxjkX5AkBIKINI\n' +
  'EhRw5zE4iBNby5S5Yt4SimxWMO8jEG9GvHrqZsUylHEp10rgcB92S8vbfINsw5KZ\n' +
  'PxkZ1+FFV89rJYOHAkBsNl1+JXvUa6U5CsKwVzjoBmW+hvGBiuTYsxRbvjdLlsEn\n' +
  '8TMKXIcwoXmy5rqK3fQ9tDg7smgzC/MPJSiI7V+z\n' +
  '-----END RSA PRIVATE KEY-----'

  if (!kid) return jwt.sign(token, key, { algorithm: 'RS256', allowInsecureKeySizes: true })
  return jwt.sign(token, key, { algorithm: 'RS256', keyid: kid, allowInsecureKeySizes: true })
}

const nockKeyset = () => {
  nock(ISS).get('/keyset').reply(200, {
    keys: [
      { kty: 'RSA', e: 'AQAB', kid: KID, n: 'VrJSr-xli8NfuAdk_Wem5BARmmW4BpJvXBx3MbFY_0grH9Cd7OxBwVYSwI4P4yhL27upa1_FCRwLi3raOPSJOkHEDvFwtyYZMvdYcpDYTv6JRVqbgEyZtHa-vjL1wBqqW75yPDRoyZdnA8MWrfyRUOak53ZVWHRKgBnP53oXm7M' }
    ]
  })
}

const lti = require('../dist/Provider/Provider')
const Storage = require('../dist/Utils/Storage')
const Auth = require('../dist/Utils/Auth')

before(async function () {
  const chaiHttp = await import('chai-http')
  chai.use(chaiHttp.default)
  chai.request = chaiHttp.request
})

describe('Testing Storage utility (LTI-CS-OIDC v0.1)', function () {
  it('Storage.sanitizeState expected to accept plain token strings and reject objects/garbage', () => {
    expect(Storage.sanitizeState('abc123xyz')).to.equal('abc123xyz')
    expect(Storage.sanitizeState({ $ne: null })).to.equal(undefined)
    expect(Storage.sanitizeState(undefined)).to.equal(undefined)
    expect(Storage.sanitizeState('bad state')).to.equal(undefined)
    expect(Storage.sanitizeState('')).to.equal(undefined)
  })

  it('Storage.sanitizeFrameName expected to accept safe frame names and fall back to _parent otherwise', () => {
    expect(Storage.sanitizeFrameName('_parent')).to.equal('_parent')
    expect(Storage.sanitizeFrameName('myFrame123')).to.equal('myFrame123')
    expect(Storage.sanitizeFrameName('opener')).to.equal('_parent')
    expect(Storage.sanitizeFrameName('__proto__')).to.equal('_parent')
    expect(Storage.sanitizeFrameName({ toString: () => 'x' })).to.equal('_parent')
    expect(Storage.sanitizeFrameName(undefined)).to.equal('_parent')
  })

  it('Storage.buildKey expected to always derive the key from state', () => {
    expect(Storage.buildKey('abc123')).to.equal('ltijs_state_abc123')
  })

  it('Storage.signValue/verifyValue expected to round-trip and return the original iss', () => {
    const signed = Storage.signValue(ISS, 'somestate123', ENCRYPTIONKEY)
    expect(Storage.verifyValue(signed, 'somestate123', ENCRYPTIONKEY)).to.equal(ISS)
  })

  it('Storage.verifyValue expected to reject a value signed for a different state', () => {
    const signed = Storage.signValue(ISS, 'somestate123', ENCRYPTIONKEY)
    expect(Storage.verifyValue(signed, 'adifferentstate', ENCRYPTIONKEY)).to.equal(undefined)
  })

  it('Storage.verifyValue expected to reject a value signed with a different key', () => {
    const signed = Storage.signValue(ISS, 'somestate123', 'WRONGENCRYPTIONKEY')
    expect(Storage.verifyValue(signed, 'somestate123', ENCRYPTIONKEY)).to.equal(undefined)
  })

  it('Storage.verifyValue expected to reject garbage/non-string/undefined values', () => {
    expect(Storage.verifyValue(undefined, 'somestate123', ENCRYPTIONKEY)).to.equal(undefined)
    expect(Storage.verifyValue('not-a-jwt', 'somestate123', ENCRYPTIONKEY)).to.equal(undefined)
    expect(Storage.verifyValue({ $ne: null }, 'somestate123', ENCRYPTIONKEY)).to.equal(undefined)
  })

  it('Storage.verifyValue expected to reject a ltik-shaped token that happens to share the ENCRYPTIONKEY (no typ discriminator)', () => {
    const ltikLike = jwt.sign({ platformUrl: ISS, s: 'somestate123' }, ENCRYPTIONKEY)
    expect(Storage.verifyValue(ltikLike, 'somestate123', ENCRYPTIONKEY)).to.equal(undefined)
  })

  it('Storage.toJs expected to produce a valid JS/JSON string literal with no literal </script breakout', () => {
    const payload = '</script><script>window.pwned=true</script>'
    const escaped = Storage.toJs(payload)
    expect(escaped).to.not.include('</script')
    expect(JSON.parse(escaped)).to.equal(payload)
  })

  it('Storage.toHtmlAttr expected to escape HTML-attribute-breaking characters', () => {
    const escaped = Storage.toHtmlAttr('"><script>alert(1)</script>')
    expect(escaped).to.equal('&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;')
  })
})

describe('Testing Auth.validateToken hardening against non-string iss/aud claims (devMode-only reachable path)', function () {
  // These claims are read via jwt.decode() before signature verification, so with devMode enabled (the only
  // way validationParameters.iss can be falsy without throwing first) they must not reach the platform lookup
  // as anything other than a string (or, for aud, a string/array-of-strings).

  it('Auth.validateToken expected to reject a non-string iss claim rather than pass it into the platform lookup', async () => {
    const token = JSON.parse(JSON.stringify(tokenValid))
    token.iss = { $ne: null }
    token.nonce = randomState()
    const payload = signToken(token, KID)

    await expect(Auth.validateToken(payload, true, { iss: undefined, maxAge: false }, lti.getPlatform, ENCRYPTIONKEY, lti.Database)).to.be.rejectedWith('INVALID_ISS_CLAIM')
  })

  it('Auth.validateToken expected to reject a non-string/non-array aud claim rather than pass it into the platform lookup', async () => {
    const token = JSON.parse(JSON.stringify(tokenValid))
    token.aud = { $ne: null }
    token.nonce = randomState()
    const payload = signToken(token, KID)

    await expect(Auth.validateToken(payload, true, { iss: undefined, maxAge: false }, lti.getPlatform, ENCRYPTIONKEY, lti.Database)).to.be.rejectedWith('INVALID_AUD_CLAIM')
  })
})

describe('Testing LTI Client Side postMessage storage handshake (LTI-CS-OIDC v0.1)', function () {
  this.timeout(10000)

  it('Login route without lti_storage_target is expected to redirect exactly as before (unchanged fast path)', async () => {
    const url = lti.loginRoute()
    nock(ISS).get(/\/AuthorizationUrl?.*/).reply(200)
    return chai.request.execute(lti.app).post(url).send({ iss: ISS, login_hint: '2', target_link_uri: 'http://localhost:3000/' }).then(res => {
      expect(res).to.redirectTo(/^http:\/\/localhost\/moodle\/AuthorizationUrl.*/)
      expect(res).to.have.status(200)
    })
  })

  it('Login route with lti_storage_target set is expected to render a put page instead of redirecting', async () => {
    const url = lti.loginRoute()
    return chai.request.execute(lti.app).post(url).send({
      iss: ISS,
      login_hint: '2',
      target_link_uri: 'http://localhost:3000/',
      lti_storage_target: '_parent'
    }).then(res => {
      expect(res).to.have.status(200)
      expect(res.headers['content-type']).to.include('text/html')
      expect(res.headers['cache-control']).to.equal('no-store')
      expect(res.text).to.include('ltijsStorageRequest')
      expect(res.text).to.include('lti.put_data')
      expect(res.text).to.include(PLATFORM_ORIGIN)
    })
  })

  it('Login route with lti_storage_target and a crafted login_hint is expected to safely escape it, no <script> breakout', async () => {
    const url = lti.loginRoute()
    const payload = '</script><script>window.pwned=true</script>'
    return chai.request.execute(lti.app).post(url).send({
      iss: ISS,
      login_hint: payload,
      target_link_uri: 'http://localhost:3000/',
      lti_storage_target: '_parent'
    }).then(res => {
      expect(res).to.have.status(200)
      expect(res.text).to.not.include('</script><script>window.pwned')
    })
  })

  it('Login route with iss/client_id as objects (NoSQL/type injection attempt) is expected to return 400', async () => {
    const url = lti.loginRoute()
    return chai.request.execute(lti.app).post(url).type('json').send({ iss: { $ne: null }, login_hint: '2', target_link_uri: 'http://localhost:3000/' }).then(res => {
      expect(res).to.have.status(400)
    })
  })

  it('Login route with target_link_uri as an object is expected to return a clean 400, not crash', async () => {
    const url = lti.loginRoute()
    return chai.request.execute(lti.app).post(url).type('json').send({ iss: ISS, login_hint: '2', target_link_uri: { $ne: null } }).then(res => {
      expect(res).to.have.status(400)
    })
  })

  it('Login route with lti_message_hint/lti_deployment_id as objects is expected to return a clean 400', async () => {
    const url = lti.loginRoute()
    return chai.request.execute(lti.app).post(url).type('json').send({ iss: ISS, login_hint: '2', target_link_uri: 'http://localhost:3000/', lti_deployment_id: { $ne: null } }).then(res => {
      expect(res).to.have.status(400)
    })
  })

  it('Callback with cookie present, storage-target used or not, is expected to succeed exactly as before (no recovery page)', async () => {
    const state = randomState()
    await lti.Database.Insert(false, 'state', { state, query: {}, storage: { platformOrigin: PLATFORM_ORIGIN, frameName: '_parent' } })

    const token = JSON.parse(JSON.stringify(tokenValid))
    token.nonce = randomState()
    const payload = signToken(token, KID)
    const url = await lti.appRoute()

    lti.onConnect((token, req, res) => res.sendStatus(200))
    nockKeyset()

    return chai.request.execute(lti.app).post(url).type('json').send({ id_token: payload, state }).set('Cookie', ['state' + state + '=' + SIGNED_ISS_COOKIE_VALUE + '; Path=/; HttpOnly;', SIGNED_SESSION_COOKIE]).then(res => {
      expect(res).to.have.status(200)
    })
  })

  it('Callback with cookie absent, no storage recorded, is expected to fail exactly as before (unchanged)', async () => {
    const state = randomState()
    const token = JSON.parse(JSON.stringify(tokenValid))
    token.nonce = randomState()
    const payload = signToken(token, KID)
    const url = await lti.appRoute()

    return chai.request.execute(lti.app).post(url).type('json').send({ id_token: payload, state }).then(res => {
      expect(res).to.have.status(401)
      expect(res.body.details.message).to.equal('MISSING_VALIDATION_COOKIE')
    })
  })

  it('Callback with cookie absent but storage-target flow recorded is expected to render a recovery page', async () => {
    const state = randomState()
    await lti.Database.Insert(false, 'state', { state, query: {}, storage: { platformOrigin: PLATFORM_ORIGIN, frameName: '_parent' } })

    const token = JSON.parse(JSON.stringify(tokenValid))
    token.nonce = randomState()
    const payload = signToken(token, KID)
    const url = await lti.appRoute()

    return chai.request.execute(lti.app).post(url).type('json').send({ id_token: payload, state }).then(res => {
      expect(res).to.have.status(200)
      expect(res.headers['content-type']).to.include('text/html')
      expect(res.headers['cache-control']).to.equal('no-store')

      const $ = cheerio.load(res.text)
      expect($('input[name="id_token"]').attr('value')).to.equal(payload)
      expect($('input[name="state"]').attr('value')).to.equal(state)
      expect($('input[name="lti_storage_recovery"]').attr('value')).to.equal('1')
      expect(res.text).to.include('lti.get_data')
      expect(res.text).to.include(PLATFORM_ORIGIN)
    })
  })

  it('Callback with cookie absent, storage-target recorded, and a crafted id_token is expected to safely escape it in the recovery page', async () => {
    const state = randomState()
    await lti.Database.Insert(false, 'state', { state, query: {}, storage: { platformOrigin: PLATFORM_ORIGIN, frameName: '_parent' } })

    const craftedIdToken = '"><script>window.pwned=true</script>'
    const url = await lti.appRoute()

    return chai.request.execute(lti.app).post(url).type('json').send({ id_token: craftedIdToken, state }).then(res => {
      expect(res).to.have.status(200)
      expect(res.text).to.not.include('"><script>window.pwned')

      const $ = cheerio.load(res.text)
      expect($('input[name="id_token"]').attr('value')).to.equal(craftedIdToken)
    })
  })

  it('Recovery resubmission with a valid signed lti_storage_iss is expected to complete the launch normally', async () => {
    const state = randomState()
    await lti.Database.Insert(false, 'state', { state, query: {}, storage: { platformOrigin: PLATFORM_ORIGIN, frameName: '_parent' } })

    const token = JSON.parse(JSON.stringify(tokenValid))
    token.nonce = randomState()
    const payload = signToken(token, KID)
    const url = await lti.appRoute()
    const signedIss = Storage.signValue(ISS, state, ENCRYPTIONKEY)

    lti.onConnect((token, req, res) => res.sendStatus(200))
    nockKeyset()

    return chai.request.execute(lti.app).post(url).type('json').send({
      id_token: payload,
      state,
      lti_storage_recovery: '1',
      lti_storage_iss: signedIss
    }).set('Cookie', [SIGNED_SESSION_COOKIE]).then(res => {
      expect(res).to.have.status(200)
    })
  })

  it('Recovery resubmission with an invalid/tampered lti_storage_iss is expected to fail like a missing cookie, without looping', async () => {
    const state = randomState()
    await lti.Database.Insert(false, 'state', { state, query: {}, storage: { platformOrigin: PLATFORM_ORIGIN, frameName: '_parent' } })

    const token = JSON.parse(JSON.stringify(tokenValid))
    token.nonce = randomState()
    const payload = signToken(token, KID)
    const url = await lti.appRoute()

    nockKeyset()

    return chai.request.execute(lti.app).post(url).type('json').send({
      id_token: payload,
      state,
      lti_storage_recovery: '1',
      lti_storage_iss: 'not-a-valid-signed-token'
    }).then(res => {
      expect(res).to.have.status(401)
      expect(res.body.details.message).to.equal('MISSING_VALIDATION_COOKIE')
      expect(res.headers['content-type']).to.not.include('text/html')
    })
  })

  it('Forged id_token with a non-string/non-array aud claim is expected to be rejected, not ignore clientId in the platform lookup', async () => {
    const token = JSON.parse(JSON.stringify(tokenValid))
    token.aud = { $ne: null }
    token.nonce = randomState()
    const payload = signToken(token, KID)
    const state = randomState()
    const url = await lti.appRoute()

    return chai.request.execute(lti.app).post(url).type('json').send({ id_token: payload, state }).set('Cookie', ['state' + state + '=' + SIGNED_ISS_COOKIE_VALUE + '; Path=/; HttpOnly;']).then(res => {
      expect(res).to.have.status(401)
    })
  })

  it('Forged state as a NoSQL operator object (idtoken present, garbage token) is not expected to delete unrelated pending state docs', async () => {
    const survivorState = randomState()
    await lti.Database.Insert(false, 'state', { state: survivorState, query: { foo: 'bar' } })

    const url = await lti.appRoute()
    return chai.request.execute(lti.app).post(url).type('json').send({ id_token: 'anything', state: { $ne: null } }).then(async res => {
      expect(res).to.have.status(401)
      const survived = await lti.Database.Get(false, 'state', { state: survivorState })
      expect(survived).to.not.equal(false)
    })
  })

  it('Forged state as a NoSQL operator object (no ltik, no idtoken - broadest reachable branch) is not expected to delete unrelated pending state docs', async () => {
    const survivorState = randomState()
    await lti.Database.Insert(false, 'state', { state: survivorState, query: { foo: 'bar' } })

    const url = await lti.appRoute()
    return chai.request.execute(lti.app).post(url).type('json').send({ state: { $ne: null } }).then(async res => {
      expect(res).to.have.status(401)
      const survived = await lti.Database.Get(false, 'state', { state: survivorState })
      expect(survived).to.not.equal(false)
    })
  })

  it('Forged state as a NoSQL operator object (outer catch block, non-JWT id_token) is not expected to delete unrelated pending state docs', async () => {
    const survivorState = randomState()
    await lti.Database.Insert(false, 'state', { state: survivorState, query: { foo: 'bar' } })

    const url = await lti.appRoute()
    return chai.request.execute(lti.app).post(url).type('json').send({ id_token: 'not-a-real-jwt', state: { $ne: null } }).then(async res => {
      expect(res).to.have.status(401)
      const survived = await lti.Database.Get(false, 'state', { state: survivorState })
      expect(survived).to.not.equal(false)
    })
  })

  it('Put page is expected to embed the default putTimeout (0, since options.ltiStorage was not set for this suite)', async () => {
    const url = lti.loginRoute()
    return chai.request.execute(lti.app).post(url).send({
      iss: ISS,
      login_hint: '2',
      target_link_uri: 'http://localhost:3000/',
      lti_storage_target: '_parent'
    }).then(res => {
      expect(res).to.have.status(200)
      expect(res.text).to.match(/var timeoutMs = 0\b/)
    })
  })

  it('Get/recovery page is expected to embed the default getTimeout (5000ms, since options.ltiStorage was not set for this suite)', async () => {
    const state = randomState()
    await lti.Database.Insert(false, 'state', { state, query: {}, storage: { platformOrigin: PLATFORM_ORIGIN, frameName: '_parent' } })
    const url = await lti.appRoute()

    return chai.request.execute(lti.app).post(url).type('json').send({ id_token: 'anything', state }).then(res => {
      expect(res).to.have.status(200)
      expect(res.text).to.match(/var timeoutMs = 5000\b/)
    })
  })
})
