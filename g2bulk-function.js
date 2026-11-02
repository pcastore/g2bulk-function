/**
 * g2bulk-function Worker (recreated from scratch — original source lost)
 * ---------------------------------------------------------------------
 * Receives G2Bulk's webhook for regular (non-voucher) game top-up orders
 * — the callback_url that fulfillG2BulkOrder() in telegram-worker.js
 * passes when it places an order (see settings/g2bulk.webhookUrl).
 *
 * Confirmed against G2Bulk's own docs (https://api.g2bulk.com/docs
 * → "Webhooks" section, fetched 2026-09-12):
 *   - POST, JSON body, fires ONLY on terminal states (COMPLETED/FAILED)
 *   - Must respond 2xx within 10s; G2Bulk retries once on failure, so
 *     this handler must be idempotent against a duplicate delivery
 *   - Body shape:
 *       { order_id, game_code, game_name, player_id, player_name,
 *         server_id, denom_id, price, status, message, remark, timestamp }
 *
 * "remark" is exactly what we sent when placing the order — fulfillG2BulkOrder()
 * sends `PCA Store order {orderId}` — so that's how this webhook maps back
 * to OUR Firestore order id (G2Bulk's own order_id is a different number,
 * saved separately as orders/{id}.g2bulkOrderId for reference only).
 *
 * ---------------- SETUP ----------------
 * Same three secrets as telegram-worker.js (same Firebase project/service
 * account, so Firestore access matches exactly):
 *   FIREBASE_PROJECT_ID
 *   FIREBASE_CLIENT_EMAIL
 *   FIREBASE_PRIVATE_KEY
 *
 * Deploy this Worker, copy its URL, and paste it into admin.html's G2Bulk
 * Settings modal as the Webhook URL (this is what gets saved to
 * settings/g2bulk.webhookUrl / .webhookSecret — the same doc
 * fulfillG2BulkOrder() reads from to build the callback_url it sends
 * G2Bulk, appending ?secret=... which this Worker checks below).
 */

const SCOPE = 'https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/firebase.messaging';
let cachedToken = null;

// ---------------------------------------------------------------------------
// Firestore REST + OAuth2 helpers (same pattern as telegram-worker.js)
// ---------------------------------------------------------------------------

function base64url(input) {
  const str = typeof input === 'string' ? btoa(input) : btoa(String.fromCharCode(...new Uint8Array(input)));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function importPrivateKey(pem) {
  const cleaned = pem.replace(/\\n/g, '\n');
  const body = cleaned
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s+/g, '');
  const der = Uint8Array.from(atob(body), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'pkcs8', der.buffer, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']
  );
}

async function getAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && cachedToken.expires > now + 60) return cachedToken.token;

  const header = { alg: 'RS256', typ: 'JWT' };
  const claim = {
    iss: env.FIREBASE_CLIENT_EMAIL,
    scope: SCOPE,
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600
  };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claim))}`;
  const key = await importPrivateKey(env.FIREBASE_PRIVATE_KEY);
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(signingInput));
  const jwt = `${signingInput}.${base64url(signature)}`;

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  });
  const data = await res.json();
  if (!data.access_token) throw new Error('Firestore auth failed: ' + JSON.stringify(data));
  cachedToken = { token: data.access_token, expires: now + (data.expires_in || 3600) };
  return cachedToken.token;
}

function firestoreDocsBase(env) {
  return `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents`;
}

function docName(env, path) {
  return `projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/${path}`;
}

function encodeValue(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'string') return { stringValue: v };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (v instanceof Date) return { timestampValue: v.toISOString() };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(encodeValue) } };
  if (typeof v === 'object') {
    const fields = {};
    for (const k in v) fields[k] = encodeValue(v[k]);
    return { mapValue: { fields } };
  }
  return { stringValue: String(v) };
}

function decodeValue(v) {
  if (!v) return null;
  const key = Object.keys(v)[0];
  switch (key) {
    case 'stringValue': return v.stringValue;
    case 'integerValue': return parseInt(v.integerValue, 10);
    case 'doubleValue': return v.doubleValue;
    case 'booleanValue': return v.booleanValue;
    case 'timestampValue': return v.timestampValue;
    case 'nullValue': return null;
    case 'mapValue': return decodeFields(v.mapValue.fields || {});
    case 'arrayValue': return (v.arrayValue.values || []).map(decodeValue);
    default: return null;
  }
}

function decodeFields(fields) {
  const out = {};
  for (const k in fields) out[k] = decodeValue(fields[k]);
  return out;
}

async function getDoc(env, path) {
  const token = await getAccessToken(env);
  const res = await fetch(`${firestoreDocsBase(env)}/${path}`, { headers: { Authorization: `Bearer ${token}` } });
  if (res.status === 404) return null;
  if (!res.ok) { console.error('getDoc failed', path, res.status, await res.text()); return null; }
  const data = await res.json();
  if (!data.fields) return null;
  return { name: data.name, updateTime: data.updateTime, fields: decodeFields(data.fields) };
}

async function patchDoc(env, path, fields, updateMaskFields) {
  const token = await getAccessToken(env);
  const encoded = {};
  for (const k in fields) encoded[k] = encodeValue(fields[k]);
  const mask = updateMaskFields.map(f => `updateMask.fieldPaths=${encodeURIComponent(f)}`).join('&');
  const res = await fetch(`${firestoreDocsBase(env)}/${path}?${mask}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ fields: encoded })
  });
  const data = await res.json();
  if (!res.ok) console.error('patchDoc failed', path, res.status, JSON.stringify(data));
  return data;
}

async function commitWrites(env, writes) {
  const token = await getAccessToken(env);
  const res = await fetch(
    `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents:commit`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ writes })
    }
  );
  const data = await res.json();
  if (!res.ok) console.error('commitWrites failed', res.status, JSON.stringify(data));
  return data;
}

// Finds our Firestore order id (and, for a multi-quantity order, which
// unit) from the webhook's echoed "remark" field. fulfillG2BulkOrder sends
// `PCA Store order {orderId}#{unitIndex}` (e.g. "...#1", "...#2" for a
// quantity-5 order, one G2Bulk call per unit since this endpoint only
// accepts quantity=1). Remarks from before that change have no "#N" suffix
// at all - treated as unit 1 of 1.
function extractOrderRefFromRemark(remark) {
  if (!remark) return null;
  const match = String(remark).match(/PCA (?:Game )?Store order (\S+?)(?:#(\d+))?$/);
  if (!match) return null;
  return { orderId: match[1], subIndex: match[2] ? Number(match[2]) : 1 };
}

// ---------------------------------------------------------------------------
// Push notification (FCM) — same approach as telegram-worker.js's
// notifyOrderStatus(), duplicated here since this is a separate deployed
// Worker with no shared module between the two.
// ---------------------------------------------------------------------------

async function sendFcmPush(env, fcmToken, title, body, data = {}) {
  if (!fcmToken) return null;
  try {
    const accessToken = await getAccessToken(env);
    const res = await fetch(
      `https://fcm.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/messages:send`,
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: { token: fcmToken, notification: { title, body }, data, webpush: { fcm_options: { link: '/' } } }
        })
      }
    );
    const result = await res.json().catch(() => ({}));
    if (!res.ok) console.error('FCM send error:', JSON.stringify(result));
    return { ok: res.ok, result };
  } catch (err) {
    console.error('FCM send exception:', err);
    return null;
  }
}

async function notifyOrderStatus(env, orderDoc, orderId, status) {
  try {
    if (!orderDoc.fields.userId) return;
    const userDoc = await getDoc(env, `users/${orderDoc.fields.userId}`);
    const fcmToken = userDoc && userDoc.fields.fcmToken;
    if (!fcmToken) return;

    const gameName = orderDoc.fields.game || 'your order';
    const title = status === 'Success' ? 'Order Completed ✅' : 'Order Failed ❌';
    const body = status === 'Success'
      ? `${gameName} — delivered successfully.`
      : `${gameName} — order failed. Tap to see details.`;

    const send = await sendFcmPush(env, fcmToken, title, body, { orderId, status });
    const errStatus = send && !send.ok && send.result && send.result.error && send.result.error.status;
    if (errStatus === 'NOT_FOUND' || errStatus === 'INVALID_ARGUMENT') {
      await patchDoc(env, `users/${orderDoc.fields.userId}`, { fcmToken: null }, ['fcmToken']);
    }
  } catch (err) {
    console.error('notifyOrderStatus error', orderId, status, err);
  }
}

// Marks the order Fail and refunds the wallet in one atomic commit if the
// order was wallet-paid - same convention as telegram-worker.js's
// finalizeWalletOrderFailure(), duplicated here for the same no-shared-module
// reason as the push helpers above.
async function finalizeFailureWithRefund(env, orderId, orderDoc, statusNote, extraFields = {}, refundAmount = null) {
  if (orderDoc.fields.status === 'Fail' && orderDoc.fields.walletRefunded) return; // already handled - idempotent

  const orderFieldsEncoded = { status: { stringValue: 'Fail' }, statusNote: { stringValue: statusNote } };
  for (const k in extraFields) orderFieldsEncoded[k] = encodeValue(extraFields[k]);
  const orderFieldPaths = ['status', 'statusNote', ...Object.keys(extraFields)];

  const amount = refundAmount === null ? Number(orderDoc.fields.price) : refundAmount;
  const eligibleForRefund = orderDoc.fields.paidFromWallet === true
    && !orderDoc.fields.walletRefunded
    && orderDoc.fields.userId
    && typeof amount === 'number' && amount > 0;

  if (!eligibleForRefund) {
    await patchDoc(env, `orders/${orderId}`, { status: 'Fail', statusNote, ...extraFields }, orderFieldPaths);
    return;
  }

  const userPath = `users/${orderDoc.fields.userId}`;
  const userDoc = await getDoc(env, userPath);
  const currentBalance = Number((userDoc && userDoc.fields.walletBalance) || 0);
  const refundedBalance = currentBalance + amount;

  orderFieldsEncoded.walletRefunded = { booleanValue: true };
  orderFieldsEncoded.refundedAt = { timestampValue: new Date().toISOString() };
  orderFieldPaths.push('walletRefunded', 'refundedAt');

  const result = await commitWrites(env, [
    {
      update: { name: docName(env, `orders/${orderId}`), fields: orderFieldsEncoded },
      updateMask: { fieldPaths: orderFieldPaths },
      currentDocument: { updateTime: orderDoc.updateTime }
    },
    {
      update: { name: docName(env, userPath), fields: { walletBalance: encodeValue(refundedBalance) } },
      updateMask: { fieldPaths: ['walletBalance'] }
    }
  ]);
  if (result.error) {
    console.error(`finalizeFailureWithRefund: commit failed for ${orderId}`, JSON.stringify(result.error));
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Adds `amount` to a user's wallet balance, independent of the order's own
// status update. Used for a multi-unit order that partially fails - the
// order itself stays "Success" (some units genuinely delivered), so this
// can't go through finalizeFailureWithRefund, which always marks Fail.
async function creditWalletRefund(env, userId, amount) {
  if (!userId || !(amount > 0)) return;
  for (let attempt = 0; attempt < 5; attempt++) {
    const userPath = `users/${userId}`;
    const userDoc = await getDoc(env, userPath);
    if (!userDoc) return;
    const currentBalance = Number(userDoc.fields.walletBalance || 0);
    const result = await commitWrites(env, [{
      update: { name: docName(env, userPath), fields: { walletBalance: encodeValue(currentBalance + amount) } },
      updateMask: { fieldPaths: ['walletBalance'] },
      currentDocument: { updateTime: userDoc.updateTime }
    }]);
    if (!result.error) return;
    await sleep(150 + Math.random() * 250); // lost the race to a concurrent write - re-read balance and retry
  }
  console.error('creditWalletRefund: gave up after retries for user', userId);
}

// Records this unit's terminal result (COMPLETED/FAILED) into the order's
// g2bulkSubOrders array and returns the updated array plus how many units
// are now done, out of the total. Firestore has no atomic "update array
// element N" operation, so this does optimistic-concurrency
// read-modify-write with a few retries in case two units' webhooks land at
// almost the same instant.
async function recordSubOrderResult(env, orderId, subIndex, terminalStatus) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const orderDoc = await getDoc(env, `orders/${orderId}`);
    if (!orderDoc) return null;
    if (orderDoc.fields.status === 'Success' || orderDoc.fields.status === 'Fail') {
      return { alreadyTerminal: true, orderDoc };
    }

    const total = Number(orderDoc.fields.g2bulkSubOrdersTotal) || 1;
    const subOrders = Array.isArray(orderDoc.fields.g2bulkSubOrders) && orderDoc.fields.g2bulkSubOrders.length
      ? orderDoc.fields.g2bulkSubOrders.slice()
      : [{ index: 1 }]; // old-style single-order doc with no sub-order tracking yet

    const idx = subOrders.findIndex(s => s && s.index === subIndex);
    if (idx === -1) subOrders.push({ index: subIndex, result: terminalStatus });
    else if (subOrders[idx].result) return { alreadyTerminal: false, orderDoc, subOrders, total, unchanged: true }; // this unit's webhook already processed - idempotent
    else subOrders[idx] = { ...subOrders[idx], result: terminalStatus };

    const doneCount = subOrders.filter(s => s.result).length;
    const result = await commitWrites(env, [{
      update: {
        name: docName(env, `orders/${orderId}`),
        fields: { g2bulkSubOrders: encodeValue(subOrders), g2bulkSubOrdersDone: encodeValue(doneCount) }
      },
      updateMask: { fieldPaths: ['g2bulkSubOrders', 'g2bulkSubOrdersDone'] },
      currentDocument: { updateTime: orderDoc.updateTime }
    }]);
    if (!result.error) return { alreadyTerminal: false, orderDoc, subOrders, total, doneCount };
    await sleep(150 + Math.random() * 250); // another unit's webhook won the race - re-read and retry
  }
  console.error('recordSubOrderResult: gave up after retries for', orderId, 'unit', subIndex);
  return null;
}

// ---------------------------------------------------------------------------
// Webhook handler
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    // Secret is a query param on the callback_url, matching how
    // fulfillG2BulkOrder() in telegram-worker.js builds it:
    //   `${g2bulk.webhookUrl}?secret=${encodeURIComponent(g2bulk.webhookSecret)}`
    const settingsDoc = await getDoc(env, 'settings/g2bulk');
    const expectedSecret = settingsDoc && settingsDoc.fields.webhookSecret;
    if (!expectedSecret || !timingSafeEqualStr(url.searchParams.get('secret') || '', expectedSecret)) {
      return new Response(JSON.stringify({ success: false, message: 'Invalid or missing secret' }), {
        status: 401, headers: { 'Content-Type': 'application/json' }
      });
    }

    // Raw body first - the signature is computed over the exact bytes G2Bulk sent.
    const rawBody = await request.text();

    // Optional second layer: G2Bulk's Standard Webhooks signature. Only enforced once
    // the G2BULK_SIGNING_SECRET (whsec_...) is set on this Worker, so nothing breaks before then.
    if (env.G2BULK_SIGNING_SECRET) {
      const ok = await verifyG2BulkSignature(env.G2BULK_SIGNING_SECRET, request, rawBody);
      if (!ok) {
        return new Response(JSON.stringify({ success: false, message: 'Bad signature' }), {
          status: 401, headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch (err) {
      return new Response(JSON.stringify({ success: false, message: 'Bad JSON' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // G2Bulk only fires this webhook on terminal states (COMPLETED/FAILED)
    // per their docs - anything else is unexpected, but respond 2xx anyway
    // so they don't keep retrying a shape we can't use.
    const status = String(payload.status || '').toUpperCase();
    const ref = extractOrderRefFromRemark(payload.remark);
    if (!ref) {
      console.error('g2bulk webhook: could not extract orderId from remark', payload.remark);
      return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
    }
    const { orderId, subIndex } = ref;
    if (status !== 'COMPLETED' && status !== 'FAILED') {
      // Not a terminal state per G2Bulk's own docs - shouldn't happen, leave the order as-is.
      return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    try {
      const rec = await recordSubOrderResult(env, orderId, subIndex, status);
      if (!rec || rec.alreadyTerminal || rec.unchanged) {
        // Order already resolved, or this exact unit's callback was already
        // processed (G2Bulk's one retry) - idempotent no-op either way.
        return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
      }

      const { orderDoc, subOrders, total, doneCount } = rec;
      if (doneCount < total) {
        // Still waiting on other units of this order - nothing more to do
        // until the last one reports in.
        return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
      }

      const failedCount = subOrders.filter(s => s.result === 'FAILED').length;
      if (failedCount === 0) {
        // Every unit delivered.
        await patchDoc(env, `orders/${orderId}`, {
          status: 'Success', confirmedAt: new Date(), g2bulkStatus: 'COMPLETED'
        }, ['status', 'confirmedAt', 'g2bulkStatus']);
        await notifyOrderStatus(env, orderDoc, orderId, 'Success');
      } else if (failedCount === total) {
        // Every unit failed - same as the old single-unit path: Fail + full refund.
        await finalizeFailureWithRefund(env, orderId, orderDoc, payload.message || 'G2Bulk order failed.', { g2bulkStatus: 'FAILED' });
        await notifyOrderStatus(env, orderDoc, orderId, 'Fail');
      } else {
        // Partial: some units delivered, some didn't. The order stays
        // Success (customer did receive `total - failedCount` units) with a
        // note, and gets refunded for just the failed units' share of the
        // price - a full order-level refund would double-pay for the
        // already-delivered units.
        const price = Number(orderDoc.fields.price) || 0;
        const perUnitRefund = Math.round(price / total);
        const refundTotal = perUnitRefund * failedCount;
        const statusNote = `Delivered ${total - failedCount}/${total} units - ${failedCount} failed`
          + (orderDoc.fields.paidFromWallet ? ` (${refundTotal.toLocaleString()} MMK refunded to wallet).` : ' - refund needs manual review (not a wallet payment).');
        await patchDoc(env, `orders/${orderId}`, {
          status: 'Success', confirmedAt: new Date(), g2bulkStatus: 'PARTIAL', statusNote
        }, ['status', 'confirmedAt', 'g2bulkStatus', 'statusNote']);
        if (orderDoc.fields.paidFromWallet === true && refundTotal > 0) {
          await creditWalletRefund(env, orderDoc.fields.userId, refundTotal);
        }
        await notifyOrderStatus(env, orderDoc, orderId, 'Success');
      }
    } catch (err) {
      console.error('g2bulk webhook processing error', orderId, err);
      // Still 200 back - G2Bulk retries once on failure, and a processing
      // error on our side isn't something a retry alone would fix anyway.
    }

    return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
  }
};

// Standard Webhooks check: HMAC-SHA256 over "{webhook-id}.{webhook-timestamp}.{raw body}",
// key = base64-decoded part after "whsec_", compared with the "v1,<sig>" value(s) in the
// webhook-signature header. Timestamps older/newer than 5 minutes are rejected.
async function verifyG2BulkSignature(secret, request, rawBody) {
  const id = request.headers.get('webhook-id');
  const ts = request.headers.get('webhook-timestamp');
  const sig = request.headers.get('webhook-signature');
  if (!id || !ts || !sig) return false;
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum) || Math.abs(Date.now() / 1000 - tsNum) > 300) return false;
  let keyBytes;
  try { keyBytes = Uint8Array.from(atob(String(secret).trim().replace(/^whsec_/, '')), c => c.charCodeAt(0)); }
  catch (e) { return false; }
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${id}.${ts}.${rawBody}`));
  const expected = btoa(String.fromCharCode(...new Uint8Array(mac)));
  return sig.split(' ').some(part => {
    const [ver, val] = part.split(',');
    return ver === 'v1' && timingSafeEqualStr(val || '', expected);
  });
}

// Constant-time string compare (the webhook secret must not be guessable via response timing).
function timingSafeEqualStr(a, b) {
  const x = new TextEncoder().encode(String(a)), y = new TextEncoder().encode(String(b));
  let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] || 0) ^ (y[i] || 0);
  return d === 0;
}
