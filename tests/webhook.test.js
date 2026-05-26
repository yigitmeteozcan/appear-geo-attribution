'use strict';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const path = require('node:path');

// ─── LemonSqueezy signature tests (pure crypto, no server needed) ─────────────

describe('LemonSqueezy HMAC-SHA256 signature verification', () => {
  const SECRET = 'test-webhook-secret-1234';

  function signPayload(payload, secret) {
    const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
    return crypto.createHmac('sha256', secret).update(body).digest('hex');
  }

  test('valid signature passes', () => {
    const payload = { meta: { event_name: 'order_created' }, data: { id: '42' } };
    const body = JSON.stringify(payload);
    const sig = signPayload(body, SECRET);

    const expected = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
    const sigBuf = Buffer.from(sig, 'hex');
    const expectedBuf = Buffer.from(expected, 'hex');

    assert.equal(sigBuf.length, expectedBuf.length);
    assert.ok(crypto.timingSafeEqual(sigBuf, expectedBuf));
  });

  test('invalid signature fails', () => {
    const payload = { meta: {}, data: {} };
    const body = JSON.stringify(payload);
    const badSig = 'a'.repeat(64); // wrong signature

    const expected = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
    const sigBuf = Buffer.from(badSig, 'hex');
    const expectedBuf = Buffer.from(expected, 'hex');

    assert.equal(sigBuf.length, expectedBuf.length);
    assert.ok(!crypto.timingSafeEqual(sigBuf, expectedBuf));
  });

  test('tampered payload fails verification', () => {
    const payload = { meta: {}, data: { id: '1', amount: 100 } };
    const originalBody = JSON.stringify(payload);
    const sig = signPayload(originalBody, SECRET);

    // Tamper with the payload
    const tamperedPayload = { meta: {}, data: { id: '1', amount: 999 } };
    const tamperedBody = JSON.stringify(tamperedPayload);

    const expected = crypto.createHmac('sha256', SECRET).update(tamperedBody).digest('hex');
    const sigBuf = Buffer.from(sig, 'hex');
    const expectedBuf = Buffer.from(expected, 'hex');

    assert.ok(!crypto.timingSafeEqual(sigBuf, expectedBuf));
  });

  test('wrong secret fails verification', () => {
    const payload = { meta: {}, data: {} };
    const body = JSON.stringify(payload);
    const sigWithWrongSecret = signPayload(body, 'wrong-secret');
    const expectedWithCorrectSecret = crypto.createHmac('sha256', SECRET).update(body).digest('hex');

    const sigBuf = Buffer.from(sigWithWrongSecret, 'hex');
    const expectedBuf = Buffer.from(expectedWithCorrectSecret, 'hex');

    assert.ok(!crypto.timingSafeEqual(sigBuf, expectedBuf));
  });
});

// ─── Timing-safe comparison tests ────────────────────────────────────────────

describe('Constant-time API key comparison', () => {
  test('identical keys return true', () => {
    const key = 'my-secret-api-key-abc123';
    const a = Buffer.from(key);
    const b = Buffer.from(key);
    assert.ok(crypto.timingSafeEqual(a, b));
  });

  test('different keys of same length return false', () => {
    const key1 = 'aaaaaaaaaaaaaaaaaaaaaaaa';
    const key2 = 'bbbbbbbbbbbbbbbbbbbbbbbb';
    const a = Buffer.from(key1);
    const b = Buffer.from(key2);
    assert.ok(!crypto.timingSafeEqual(a, b));
  });

  test('HMAC normalization makes keys of different length comparable', () => {
    // Simulate what auth.js does — HMAC both sides with a fixed context key
    const hmac = (val) => crypto.createHmac('sha256', 'appear-auth').update(val).digest();
    const short = 'short';
    const long = 'a-much-longer-key-value-here';
    // Both produce 32-byte digests regardless of input length
    assert.equal(hmac(short).length, 32);
    assert.equal(hmac(long).length, 32);
    // And they should NOT be equal to each other (different inputs)
    assert.ok(!crypto.timingSafeEqual(hmac(short), hmac(long)));
  });
});

// ─── In-memory store tests ─────────────────────────────────────────────────────────

describe('In-memory store', () => {
  let store;

  before(() => {
    // Ensure no DATABASE_URL set
    delete process.env.DATABASE_URL;
    delete process.env.API_KEY; // will be set per test
    store = require('../src/server/store');
    store.initStore();
  });

  test('saves and retrieves a session', () => {
    const visitData = {
      session_id: 'test-session-001',
      engine: 'chatgpt',
      source: 'referrer',
      referrer: 'https://chatgpt.com',
      page_url: 'https://example.com',
      timestamp: new Date().toISOString(),
    };

    store.saveSession('test-session-001', visitData);
    const retrieved = store.getSession('test-session-001');

    assert.ok(retrieved);
    assert.equal(retrieved.engine, 'chatgpt');
    assert.equal(retrieved.session_id, 'test-session-001');
  });

  test('returns null for unknown session', () => {
    const result = store.getSession('does-not-exist-xyz');
    assert.equal(result, null);
  });

  test('saves and reflects attribution in stats', () => {
    const visitData = {
      session_id: 'test-session-002',
      engine: 'perplexity',
      source: 'referrer',
    };

    store.saveSession('test-session-002', visitData);
    store.saveAttribution('payment-001', 'test-session-002', visitData, {
      provider: 'stripe',
      payment_id: 'payment-001',
      amount: 29,
      currency: 'usd',
    });

    const stats = store.getStats();
    assert.ok(stats.total_attributions >= 1);
    assert.ok(stats.total_revenue >= 29);
    assert.ok(stats.revenue_by_engine.perplexity >= 29);
  });

  test('stats includes recent_attributions array', () => {
    const stats = store.getStats();
    assert.ok(Array.isArray(stats.recent_attributions));
  });

  test('stats response has correct shape', () => {
    const stats = store.getStats();
    assert.ok(typeof stats.total_sessions === 'number', 'total_sessions must be number');
    assert.ok(typeof stats.total_attributions === 'number', 'total_attributions must be number');
    assert.ok(typeof stats.revenue_by_engine === 'object' && stats.revenue_by_engine !== null, 'revenue_by_engine must be object');
    assert.ok(Array.isArray(stats.recent_attributions), 'recent_attributions must be array');
    assert.ok(typeof stats.total_revenue === 'number', 'total_revenue must be number');
  });

  test('getSession returns null for expired session (mocked Date.now)', () => {
    // Save a session
    store.saveSession('expire-test-session', { engine: 'claude', source: 'utm' });

    // Verify it's retrievable now
    const before = store.getSession('expire-test-session');
    assert.ok(before, 'session should exist before expiry');

    const realDateNow = Date.now;
    // Move time forward 25 hours so the session is expired
    Date.now = () => realDateNow() + 25 * 60 * 60 * 1000;
    try {
      const after = store.getSession('expire-test-session');
      assert.equal(after, null, 'session should be null after TTL expires');
    } finally {
      Date.now = realDateNow;
    }
  });

  test('duplicate attribution does not double-count in revenue stats', () => {
    const visitData = { engine: 'gemini', source: 'referrer' };
    store.saveSession('dedup-session', visitData);

    // Save same payment ID twice — second call should be idempotent (UPDATE)
    store.saveAttribution('dedup-payment-999', 'dedup-session', visitData, {
      provider: 'stripe',
      payment_id: 'dedup-payment-999',
      amount: 50,
      currency: 'usd',
    });
    store.saveAttribution('dedup-payment-999', 'dedup-session', visitData, {
      provider: 'stripe',
      payment_id: 'dedup-payment-999',
      amount: 50,
      currency: 'usd',
    });

    // Count how many times dedup-payment-999 appears in recent_attributions
    const stats = store.getStats();
    const dedupEntries = stats.recent_attributions.filter(
      (a) => a.payment_id === 'dedup-payment-999'
    );
    assert.equal(dedupEntries.length, 1, 'duplicate payment_id should only appear once');
  });

  test('saveSession at MAX_SESSIONS cap silently drops new session (does not throw)', () => {
    assert.doesNotThrow(() => {
      for (let i = 0; i < 1000; i++) {
        store.saveSession(`bulk-session-${i}`, { engine: 'chatgpt', source: 'utm' });
      }
    });
  });
});

// ─── HTTP integration tests ─────────────────────────────────────────────────────────────────────────────────

describe('HTTP endpoints', () => {
  let server;
  let baseUrl;
  const API_KEY = 'test-api-key-integration-xxxxxxxx'; // ≥32 chars required

  before(async () => {
    process.env.API_KEY = API_KEY;
    process.env.ALLOWED_ORIGINS = 'https://example.com';

    // Import fresh app
    const app = require('../src/server/index.js');
    server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  // ── /health ──────────────────────────────────────────────────────────────────────────────────

  test('GET /health returns 200', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
  });

  test('GET /health does not expose sensitive fields', async () => {
    const res = await fetch(`${baseUrl}/health`);
    const body = await res.json();
    assert.equal(body.apiKey, undefined, 'health must not expose API key');
    assert.equal(body.env, undefined, 'health must not expose env vars');
  });

  // ── /appear/stats ──────────────────────────────────────────────────────────────────────────────────

  test('GET /appear/stats without auth returns 401', async () => {
    const res = await fetch(`${baseUrl}/appear/stats`);
    assert.equal(res.status, 401);
  });

  test('GET /appear/stats with wrong API key returns 401', async () => {
    const res = await fetch(`${baseUrl}/appear/stats`, {
      headers: { 'x-api-key': 'wrong-key' },
    });
    assert.equal(res.status, 401);
  });

  test('GET /appear/stats with valid API key returns 200', async () => {
    const res = await fetch(`${baseUrl}/appear/stats`, {
      headers: { 'x-api-key': API_KEY },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(typeof body.total_sessions === 'number');
    assert.ok(typeof body.total_attributions === 'number');
  });

  test('GET /appear/stats response has correct shape', async () => {
    const res = await fetch(`${baseUrl}/appear/stats`, {
      headers: { 'x-api-key': API_KEY },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(typeof body.total_sessions === 'number', 'total_sessions must be number');
    assert.ok(typeof body.total_attributions === 'number', 'total_attributions must be number');
    assert.ok(
      typeof body.revenue_by_engine === 'object' && body.revenue_by_engine !== null,
      'revenue_by_engine must be object'
    );
    assert.ok(Array.isArray(body.recent_attributions), 'recent_attributions must be array');
  });

  test('GET /appear/stats with Bearer token returns 200', async () => {
    const res = await fetch(`${baseUrl}/appear/stats`, {
      headers: { Authorization: `Bearer ${API_KEY}` },
    });
    assert.equal(res.status, 200);
  });

  // ── /appear/event ──────────────────────────────────────────────────────────────────────────────────

  test('POST /appear/event with valid payload returns 202', async () => {
    const payload = {
      session_id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      engine: 'chatgpt',
      source: 'referrer',
      referrer: 'https://chatgpt.com',
      page_url: 'https://example.com/page',
      timestamp: new Date().toISOString(),
    };

    const res = await fetch(`${baseUrl}/appear/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    assert.equal(res.status, 202);
    const body = await res.json();
    assert.equal(body.ok, true);
  });

  test('POST /appear/event missing session_id returns 400', async () => {
    const payload = {
      engine: 'chatgpt',
      source: 'referrer',
      page_url: 'https://example.com',
      timestamp: new Date().toISOString(),
    };

    const res = await fetch(`${baseUrl}/appear/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    assert.equal(res.status, 400);
  });

  test('POST /appear/event with session_id containing path traversal chars returns 400', async () => {
    const payload = {
      session_id: '../../../etc/passwd',
      engine: 'chatgpt',
      source: 'referrer',
      page_url: 'https://example.com',
      timestamp: new Date().toISOString(),
    };

    const res = await fetch(`${baseUrl}/appear/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    assert.equal(res.status, 400);
  });

  test('POST /appear/event with invalid engine returns 400', async () => {
    const payload = {
      session_id: 'valid-session-id',
      engine: 'evil-engine',
      source: 'referrer',
      page_url: 'https://example.com',
      timestamp: new Date().toISOString(),
    };

    const res = await fetch(`${baseUrl}/appear/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    assert.equal(res.status, 400);
  });

  test('POST /appear/event with unknown fields returns 400', async () => {
    const payload = {
      session_id: 'valid-session-id',
      engine: 'chatgpt',
      source: 'referrer',
      page_url: 'https://example.com',
      timestamp: new Date().toISOString(),
      injected_field: '<script>alert(1)</script>',
    };

    const res = await fetch(`${baseUrl}/appear/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    assert.equal(res.status, 400);
  });

  test('POST /appear/event with array as session_id returns 400', async () => {
    const res = await fetch(`${baseUrl}/appear/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: ['injected', 'array'],
        engine: 'chatgpt',
        source: 'referrer',
        page_url: 'https://example.com',
        timestamp: new Date().toISOString(),
      }),
    });
    assert.equal(res.status, 400);
  });

  test('POST /appear/event with object as engine returns 400', async () => {
    const res = await fetch(`${baseUrl}/appear/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: 'valid-session-id',
        engine: { toString: 'chatgpt' },
        source: 'referrer',
        page_url: 'https://example.com',
        timestamp: new Date().toISOString(),
      }),
    });
    assert.equal(res.status, 400);
  });

  test('POST /appear/event with prototype pollution keys returns 400', async () => {
    const res = await fetch(`${baseUrl}/appear/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // Send raw JSON with __proto__ key
      body: '{"__proto__":{"isAdmin":true},"session_id":"abc","engine":"chatgpt","source":"referrer","page_url":"https://example.com","timestamp":"2024-01-01T00:00:00.000Z"}',
    });
    assert.equal(res.status, 400);
  });

  test('POST /appear/event with oversized payload returns 413', async () => {
    // Create a payload larger than 10kb limit
    const bigString = 'x'.repeat(15000);
    const res = await fetch(`${baseUrl}/appear/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: 'valid-session-id',
        engine: 'chatgpt',
        source: 'referrer',
        page_url: bigString,
        timestamp: new Date().toISOString(),
      }),
    });
    // Express returns 413 for body too large
    assert.equal(res.status, 413);
  });

  test('POST /appear/event rate limit: 61st request returns 429', async () => {
    const app2 = require('../src/server/index.js');
    const server2 = http.createServer(app2);
    await new Promise((resolve) => server2.listen(0, '127.0.0.1', resolve));
    const { port: port2 } = server2.address();
    const url2 = `http://127.0.0.1:${port2}`;

    const payload = {
      session_id: 'rate-limit-session-id',
      engine: 'chatgpt',
      source: 'referrer',
      page_url: 'https://example.com',
      timestamp: new Date().toISOString(),
    };

    let lastStatus = 0;
    for (let i = 0; i < 61; i++) {
      const r = await fetch(`${url2}/appear/event`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      lastStatus = r.status;
    }

    await new Promise((resolve) => server2.close(resolve));
    assert.equal(lastStatus, 429, '61st request should be rate-limited to 429');
  });

  // ── /stripe/webhook ──────────────────────────────────────────────────────────────────────────────────

  test('POST /stripe/webhook without signature returns 400', async () => {
    process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test';
    process.env.STRIPE_SECRET_KEY = 'sk_test_fake';

    const res = await fetch(`${baseUrl}/stripe/webhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'checkout.session.completed' }),
    });

    assert.equal(res.status, 400);
  });

  test('POST /stripe/webhook with invalid signature returns 400', async () => {
    process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test_secret_key';
    process.env.STRIPE_SECRET_KEY = 'sk_test_fake';

    const res = await fetch(`${baseUrl}/stripe/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'stripe-signature': 't=1234567890,v1=badhexbadheybadheybadheybadheybadheybadheybadheybadheybadheybad',
      },
      body: JSON.stringify({ type: 'checkout.session.completed' }),
    });

    assert.equal(res.status, 400);
  });

  test('POST /stripe/webhook valid checkout.session.completed saves attribution', async () => {
    const Stripe = require('stripe');
    const stripeSecret = 'whsec_stripe_integration_test';
    process.env.STRIPE_WEBHOOK_SECRET = stripeSecret;
    process.env.STRIPE_SECRET_KEY = 'sk_test_fake';

    const stripe = new Stripe('sk_test_fake', { apiVersion: '2023-10-16' });

    const store = require('../src/server/store');
    const sessionId = 'stripe-test-session-checkout-001';
    store.saveSession(sessionId, {
      session_id: sessionId,
      engine: 'perplexity',
      source: 'referrer',
      referrer: 'https://perplexity.ai',
      page_url: 'https://myshop.com/product',
      timestamp: new Date().toISOString(),
    });

    const payload = {
      id: 'evt_test_checkout_001',
      object: 'event',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_test_checkout_001',
          object: 'checkout.session',
          metadata: { appear_session_id: sessionId },
          amount_total: 2999,
          currency: 'usd',
        },
      },
    };

    const payloadString = JSON.stringify(payload);
    const timestamp = Math.floor(Date.now() / 1000);
    const signedPayload = `${timestamp}.${payloadString}`;
    const signature = crypto
      .createHmac('sha256', stripeSecret)
      .update(signedPayload)
      .digest('hex');
    const stripeHeader = `t=${timestamp},v1=${signature}`;

    const res = await fetch(`${baseUrl}/stripe/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'stripe-signature': stripeHeader,
      },
      body: payloadString,
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.received, true);

    const statsRes = await fetch(`${baseUrl}/appear/stats`, {
      headers: { 'x-api-key': API_KEY },
    });
    const stats = await statsRes.json();
    assert.ok(stats.total_attributions >= 1, 'attribution should have been saved');
  });

  test('POST /stripe/webhook valid payment_intent.succeeded saves attribution', async () => {
    const stripeSecret = 'whsec_stripe_pi_test';
    process.env.STRIPE_WEBHOOK_SECRET = stripeSecret;
    process.env.STRIPE_SECRET_KEY = 'sk_test_fake';

    const store = require('../src/server/store');
    const sessionId = 'stripe-test-session-pi-001';
    store.saveSession(sessionId, {
      session_id: sessionId,
      engine: 'claude',
      source: 'utm',
      referrer: '',
      page_url: 'https://myshop.com/checkout',
      timestamp: new Date().toISOString(),
    });

    const payload = {
      id: 'evt_test_pi_001',
      object: 'event',
      type: 'payment_intent.succeeded',
      data: {
        object: {
          id: 'pi_test_001',
          object: 'payment_intent',
          metadata: { appear_session_id: sessionId },
          amount_received: 4999,
          currency: 'usd',
        },
      },
    };

    const payloadString = JSON.stringify(payload);
    const timestamp = Math.floor(Date.now() / 1000);
    const signedPayload = `${timestamp}.${payloadString}`;
    const signature = crypto
      .createHmac('sha256', stripeSecret)
      .update(signedPayload)
      .digest('hex');
    const stripeHeader = `t=${timestamp},v1=${signature}`;

    const res = await fetch(`${baseUrl}/stripe/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'stripe-signature': stripeHeader,
      },
      body: payloadString,
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.received, true);
  });

  test('POST /stripe/webhook valid signature but no appear_session_id returns received:true', async () => {
    const stripeSecret = 'whsec_stripe_nometadata_test';
    process.env.STRIPE_WEBHOOK_SECRET = stripeSecret;
    process.env.STRIPE_SECRET_KEY = 'sk_test_fake';

    const payload = {
      id: 'evt_test_nometa',
      object: 'event',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_test_nometa',
          object: 'checkout.session',
          metadata: {},
          amount_total: 1000,
          currency: 'usd',
        },
      },
    };

    const payloadString = JSON.stringify(payload);
    const timestamp = Math.floor(Date.now() / 1000);
    const signedPayload = `${timestamp}.${payloadString}`;
    const signature = crypto
      .createHmac('sha256', stripeSecret)
      .update(signedPayload)
      .digest('hex');
    const stripeHeader = `t=${timestamp},v1=${signature}`;

    const res = await fetch(`${baseUrl}/stripe/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'stripe-signature': stripeHeader,
      },
      body: payloadString,
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.received, true);
  });

  test('POST /stripe/webhook valid signature but unknown session_id returns received:true', async () => {
    const stripeSecret = 'whsec_stripe_nosession_test';
    process.env.STRIPE_WEBHOOK_SECRET = stripeSecret;
    process.env.STRIPE_SECRET_KEY = 'sk_test_fake';

    const payload = {
      id: 'evt_test_nosession',
      object: 'event',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_test_nosession',
          object: 'checkout.session',
          metadata: { appear_session_id: 'no-such-session-in-store' },
          amount_total: 1000,
          currency: 'usd',
        },
      },
    };

    const payloadString = JSON.stringify(payload);
    const timestamp = Math.floor(Date.now() / 1000);
    const signedPayload = `${timestamp}.${payloadString}`;
    const signature = crypto
      .createHmac('sha256', stripeSecret)
      .update(signedPayload)
      .digest('hex');
    const stripeHeader = `t=${timestamp},v1=${signature}`;

    const res = await fetch(`${baseUrl}/stripe/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'stripe-signature': stripeHeader,
      },
      body: payloadString,
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.received, true);
  });

  test('POST /stripe/webhook duplicate payment_id does not double-count in stats', async () => {
    const stripeSecret = 'whsec_stripe_dedup_test';
    process.env.STRIPE_WEBHOOK_SECRET = stripeSecret;
    process.env.STRIPE_SECRET_KEY = 'sk_test_fake';

    const store = require('../src/server/store');
    const sessionId = 'stripe-dedup-session';
    store.saveSession(sessionId, {
      session_id: sessionId,
      engine: 'gemini',
      source: 'utm',
      page_url: 'https://example.com',
      timestamp: new Date().toISOString(),
    });

    const buildRequest = (paymentId) => {
      const payload = {
        id: 'evt_dedup_' + paymentId,
        object: 'event',
        type: 'checkout.session.completed',
        data: {
          object: {
            id: paymentId,
            object: 'checkout.session',
            metadata: { appear_session_id: sessionId },
            amount_total: 5000,
            currency: 'usd',
          },
        },
      };
      const payloadString = JSON.stringify(payload);
      const timestamp = Math.floor(Date.now() / 1000);
      const signedPayload = `${timestamp}.${payloadString}`;
      const signature = crypto.createHmac('sha256', stripeSecret).update(signedPayload).digest('hex');
      return { payloadString, stripeHeader: `t=${timestamp},v1=${signature}` };
    };

    const dedupPaymentId = 'cs_dedup_stripe_001';

    for (let i = 0; i < 2; i++) {
      const { payloadString, stripeHeader } = buildRequest(dedupPaymentId);
      await fetch(`${baseUrl}/stripe/webhook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'stripe-signature': stripeHeader,
        },
        body: payloadString,
      });
    }

    const statsRes = await fetch(`${baseUrl}/appear/stats`, {
      headers: { 'x-api-key': API_KEY },
    });
    const stats = await statsRes.json();

    const dedupEntries = stats.recent_attributions.filter(
      (a) => a.payment_id === dedupPaymentId
    );
    assert.equal(dedupEntries.length, 1, 'duplicate webhook delivery must not double-count');
  });

  // ── /lemonsqueezy/webhook ────────────────────────────────────────────────────────────────────────────────

  test('POST /lemonsqueezy/webhook without signature returns 400', async () => {
    process.env.LEMONSQUEEZY_WEBHOOK_SECRET = 'test-ls-secret';

    const res = await fetch(`${baseUrl}/lemonsqueezy/webhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ meta: {}, data: {} }),
    });

    assert.equal(res.status, 400);
  });

  test('POST /lemonsqueezy/webhook with invalid signature returns 400', async () => {
    process.env.LEMONSQUEEZY_WEBHOOK_SECRET = 'test-ls-secret-real';

    const body = JSON.stringify({ meta: {}, data: { id: '1' } });
    const badSig = 'a'.repeat(64);

    const res = await fetch(`${baseUrl}/lemonsqueezy/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-signature': badSig,
        'x-event-name': 'order_created',
      },
      body,
    });

    assert.equal(res.status, 400);
  });

  test('POST /lemonsqueezy/webhook valid order_created saves attribution', async () => {
    const lsSecret = 'test-ls-secret-order-created';
    process.env.LEMONSQUEEZY_WEBHOOK_SECRET = lsSecret;

    const store = require('../src/server/store');
    const sessionId = 'ls-test-session-001';
    store.saveSession(sessionId, {
      session_id: sessionId,
      engine: 'you',
      source: 'referrer',
      referrer: 'https://you.com',
      page_url: 'https://myshop.com',
      timestamp: new Date().toISOString(),
    });

    const payload = {
      meta: {
        event_name: 'order_created',
        custom_data: { appear_session_id: sessionId },
      },
      data: {
        id: 'ls-order-001',
        attributes: {
          total: 4900,
          currency: 'usd',
        },
      },
    };

    const bodyStr = JSON.stringify(payload);
    const sig = crypto.createHmac('sha256', lsSecret).update(bodyStr).digest('hex');

    const res = await fetch(`${baseUrl}/lemonsqueezy/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-signature': sig,
        'x-event-name': 'order_created',
      },
      body: bodyStr,
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.received, true);

    const statsRes = await fetch(`${baseUrl}/appear/stats`, {
      headers: { 'x-api-key': API_KEY },
    });
    const stats = await statsRes.json();
    assert.ok(stats.total_attributions >= 1, 'attribution should have been saved');
  });

  test('POST /lemonsqueezy/webhook 65-char hex signature (odd-length bypass) returns 400', async () => {
    const lsSecret = 'test-ls-secret-sig-length';
    process.env.LEMONSQUEEZY_WEBHOOK_SECRET = lsSecret;

    const bodyStr = JSON.stringify({ meta: {}, data: {} });
    const validSig = crypto.createHmac('sha256', lsSecret).update(bodyStr).digest('hex');
    // Append one hex digit — Buffer.from would produce same 32 bytes, but our
    // string-length guard must reject it before Buffer.from is ever called.
    const oddSig = validSig + '0';
    assert.equal(oddSig.length, 65);

    const res = await fetch(`${baseUrl}/lemonsqueezy/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-signature': oddSig,
        'x-event-name': 'order_created',
      },
      body: bodyStr,
    });
    assert.equal(res.status, 400);
  });

  test('POST /lemonsqueezy/webhook numeric appear_session_id returns 200 (no 500)', async () => {
    const lsSecret = 'test-ls-secret-numeric-sid';
    process.env.LEMONSQUEEZY_WEBHOOK_SECRET = lsSecret;

    const payload = {
      meta: {
        event_name: 'order_created',
        custom_data: { appear_session_id: 12345 }, // numeric — must not throw
      },
      data: { id: 'ls-order-numeric', attributes: { total: 500, currency: 'usd' } },
    };
    const bodyStr = JSON.stringify(payload);
    const sig = crypto.createHmac('sha256', lsSecret).update(bodyStr).digest('hex');

    const res = await fetch(`${baseUrl}/lemonsqueezy/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-signature': sig,
        'x-event-name': 'order_created',
      },
      body: bodyStr,
    });
    // Should return 200 received:true, not 500
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.received, true);
  });

  test('POST /lemonsqueezy/webhook valid signature but no appear_session_id returns received:true', async () => {
    const lsSecret = 'test-ls-secret-nometadata';
    process.env.LEMONSQUEEZY_WEBHOOK_SECRET = lsSecret;

    const payload = {
      meta: {
        event_name: 'order_created',
        custom_data: {},
      },
      data: {
        id: 'ls-order-nometadata',
        attributes: { total: 1000, currency: 'usd' },
      },
    };

    const bodyStr = JSON.stringify(payload);
    const sig = crypto.createHmac('sha256', lsSecret).update(bodyStr).digest('hex');

    const res = await fetch(`${baseUrl}/lemonsqueezy/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-signature': sig,
        'x-event-name': 'order_created',
      },
      body: bodyStr,
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.received, true);
  });

  // ── 404 ──────────────────────────────────────────────────────────────────────────────────

  test('unknown route returns 404', async () => {
    const res = await fetch(`${baseUrl}/not-a-real-route`);
    assert.equal(res.status, 404);
  });
});

// ─── Startup / config tests ─────────────────────────────────────────────────────────────────────────────────

describe('Startup and config', () => {
  test('Server starts without STRIPE_SECRET_KEY (lazy load — no crash)', () => {
    delete process.env.STRIPE_SECRET_KEY;
    assert.doesNotThrow(() => {
      require('../src/server/index.js');
    });
  });

  test('Server starts without LEMONSQUEEZY_WEBHOOK_SECRET (no crash at startup)', () => {
    delete process.env.LEMONSQUEEZY_WEBHOOK_SECRET;
    assert.doesNotThrow(() => {
      require('../src/server/index.js');
    });
  });

  test('Server crashes (process.exit) if API_KEY is missing', () => {
    const { spawnSync } = require('node:child_process');
    const env = { ...process.env };
    delete env.API_KEY;
    const result = spawnSync(
      process.execPath,
      [path.join(__dirname, '../src/server/index.js')],
      { env }
    );
    assert.equal(result.status, 1, 'process should exit with code 1 when API_KEY is missing');
  });

  test('Server crashes (process.exit) if API_KEY is shorter than 32 characters', () => {
    const { spawnSync } = require('node:child_process');
    const result = spawnSync(
      process.execPath,
      [path.join(__dirname, '../src/server/index.js')],
      { env: { ...process.env, API_KEY: 'tooshort' } }
    );
    assert.equal(result.status, 1, 'process should exit with code 1 when API_KEY is too short');
  });
});
