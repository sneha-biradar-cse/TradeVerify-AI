/* TradeVerify AI v6 — Stripe test-mode hosted card flow + pre-authorization fraud gate. */
(function () {
  const $ = (id) => document.getElementById(id);
  let checkoutSession = sessionStorage.getItem('tv_checkout_session');
  // A different login (new token) starts a fresh checkout session, so a previous account's block is never inherited.
  const _owner = (localStorage.getItem('tv_session_token') || '').slice(-16);
  if (sessionStorage.getItem('tv_checkout_owner') !== _owner) { checkoutSession = null; sessionStorage.setItem('tv_checkout_owner', _owner); }
  if (!checkoutSession) {
    checkoutSession = 'checkout-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
    sessionStorage.setItem('tv_checkout_session', checkoutSession);
  }

  let stripe = null;
  let stripeCard = null;
  let stripeReady = false;
  let paymentMode = null;
  let paymentIntentId = null;
  let paymentClientSecret = null;
  let localTestCards = [];

  function setDrawer(id, open) {
    const el = $(id); if (!el) return;
    el.classList.toggle('hidden', !open);
    el.setAttribute('aria-hidden', open ? 'false' : 'true');
    document.body.classList.toggle('drawer-open', open || document.querySelector('.drawer-overlay:not(.hidden)'));
    if (open) setTimeout(() => el.querySelector('input')?.focus(), 80);
    if (open && id === 'paymentDrawer') setTimeout(initPaymentCheckout, 120);
  }
  window.openPaymentDrawer = function () {
    setDrawer('paymentDrawer', true);
    try { fetch('/api/payments/form-opened', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({token: sessionToken()})}); } catch (e) {}
  };
  window.closePaymentDrawer = function () { setDrawer('paymentDrawer', false); };
  window.openFraudTestDrawer = function () { setDrawer('fraudTestDrawer', true); };
  window.closeFraudTestDrawer = function () { setDrawer('fraudTestDrawer', false); };

  let labEnabled = false;   // the demo Fraud Test Lab is shown only when the server says ENABLE_TEST_LAB=1
  const BOT_ALERT_TEXT = '\u26A0 Account may be under attack by a bot. Payments were submitted faster than a human can, so this account has been blocked for security. Please contact your administrator to restore access.';
  // One place decides how a blocked payment is worded; a bot block gets its own red alert.
  function showBlocked(res, suffix) {
    if (res && res.block_kind === 'bot') { showPaymentResult(BOT_ALERT_TEXT, 'botalert'); return; }
    const mins = Math.max(1, Math.round((((res && res.carding_audit && res.carding_audit.retry_after_seconds) || 900)) / 60));
    showPaymentResult('Payment paused for security \u2014 ' + ((res && res.block_reason) || 'suspicious payment activity detected') + '. If you are a genuine customer, please try again in about ' + mins + ' minutes or contact support.', 'blocked');
  }
  const RESULT_META = {
    ok:{icon:'\u2713',title:'Payment successful'}, declined:{icon:'!',title:'Payment declined'},
    stepup:{icon:'!',title:'Action needed'}, blocked:{icon:'\u2715',title:'Payment paused'},
    botalert:{icon:'\u2715',title:'Account blocked'}, error:{icon:'\u2715',title:'Something went wrong'},
    info:{icon:'i',title:'Payment status'}, unlocked:{icon:'\u2713',title:'Account unblocked'}, verified:{icon:'\u2713',title:'Verification complete'}
  };
  function showPaymentResult(text, kind) {
    const el = $('pf-result'); if (!el) return;
    const k = RESULT_META[kind] ? kind : 'info';
    el.className = 'payment-result ' + k;
    el.innerHTML = '';
    const icon = document.createElement('span'); icon.className = 'pr-icon'; icon.textContent = RESULT_META[k].icon;
    const body = document.createElement('div');
    const t = document.createElement('span'); t.className = 'pr-title'; t.textContent = RESULT_META[k].title;
    const m = document.createElement('span'); m.className = 'pr-text'; m.textContent = text;
    body.appendChild(t); body.appendChild(m); el.appendChild(icon); el.appendChild(body);
    if (k === 'blocked' || k === 'botalert') offerSelfUnlock(body);
  }

  // ---- Human check (Cloudflare Turnstile) on the first too-fast payment ----
  let turnstileLoading = null;
  function loadTurnstile() {
    if (window.turnstile) return Promise.resolve();
    if (!turnstileLoading) turnstileLoading = new Promise((resolve, reject) => {
      const sc = document.createElement('script');
      sc.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      sc.async = true; sc.onload = () => resolve(); sc.onerror = () => { turnstileLoading = null; reject(new Error('load')); };
      document.head.appendChild(sc);
    });
    return turnstileLoading;
  }
  async function showCaptchaChallenge(data) {
    showPaymentResult(data.captcha_purpose === 'stepup'
      ? 'For your security we need one quick extra check. Complete it below, then press Pay again.'
      : data.captcha_purpose === 'card'
      ? (data.error || 'Please complete a quick check before trying another card.')
      : 'Payments are being submitted faster than normal. Please complete this quick check to continue. If it happens again, this account will be blocked.', 'stepup');
    const host = $('pf-result') && $('pf-result').lastElementChild; if (!host) return;
    const box = document.createElement('div'); box.className = 'unlock-box';
    const mount = document.createElement('div'); mount.className = 'captcha-mount'; box.appendChild(mount);
    const note = document.createElement('div'); note.className = 'unlock-note'; box.appendChild(note);
    host.appendChild(box);
    try {
      await loadTurnstile();
      window.turnstile.render(mount, {
        sitekey: data.captcha_site_key, theme: 'light',
        callback: async (captchaResponse) => {
          note.style.color = '#555'; note.textContent = 'Checking...';
          try {
            const r = await fetch('/api/payments/captcha/verify', {method:'POST', headers:{'Content-Type':'application/json'},
              body: JSON.stringify({token: sessionToken(), session_id: checkoutSession || '', captcha_response: captchaResponse, purpose: data.captcha_purpose || 'speed'})});
            const d = await r.json();
            if (d.success) { showPaymentResult(d.message, 'verified'); return; }
            note.style.color = '#b42318'; note.textContent = d.error || 'The check did not pass.';
            try { window.turnstile.reset(mount); } catch (e) {}
          } catch (e) { note.style.color = '#b42318'; note.textContent = 'Network error. Please try again.'; }
        }
      });
    } catch (e) {
      note.style.color = '#b42318';
      note.textContent = 'The check could not load (no internet?). Please wait a few seconds before trying again.';
    }
  }

  // ---- Block reference ID + self-unlock with a one-time code (first-time locks only) ----
  async function offerSelfUnlock(host) {
    const tok = sessionToken(); if (!tok) return;
    try {
      const r = await fetch('/api/account/security-status', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({token:tok})});
      const d = await r.json();
      if (!d.success || d.state !== 'blocked') return;
      const box = document.createElement('div'); box.className = 'unlock-box';
      if (d.reference) { const ref = document.createElement('div'); ref.className = 'unlock-ref'; ref.textContent = 'Reference: ' + d.reference; box.appendChild(ref); }
      const msg = document.createElement('div'); msg.className = 'unlock-msg'; msg.textContent = d.unlock_message || ''; box.appendChild(msg);
      if (d.can_self_unlock) {
        const btn = document.createElement('button'); btn.type = 'button'; btn.className = 'unlock-btn'; btn.textContent = "Verify it's me to unblock";
        btn.addEventListener('click', () => requestUnlockCode(box, btn));
        box.appendChild(btn);
      }
      host.appendChild(box);
    } catch (e) { /* the reference is a convenience; ignore network hiccups */ }
  }
  async function requestUnlockCode(box, btn) {
    btn.disabled = true;
    try {
      const r = await fetch('/api/account/unlock-request', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({token:sessionToken()})});
      const d = await r.json();
      if (!d.success) { btn.disabled = false; unlockNote(box, d.error || 'Could not send a code.', true); return; }
      btn.remove();
      const row = document.createElement('div'); row.className = 'unlock-row';
      const inp = document.createElement('input'); inp.inputMode = 'numeric'; inp.maxLength = 6; inp.placeholder = '6-digit code'; inp.autocomplete = 'one-time-code';
      const go = document.createElement('button'); go.type = 'button'; go.className = 'unlock-btn'; go.textContent = 'Unblock';
      go.addEventListener('click', () => submitUnlockCode(box, inp, go));
      inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') go.click(); });
      row.appendChild(inp); row.appendChild(go); box.appendChild(row);
      unlockNote(box, (d.message || 'We sent a one-time code to your account email.') + (d.demo_otp_code ? ' (Development mode: your code is ' + d.demo_otp_code + ')' : ''), false);
      inp.focus();
    } catch (e) { btn.disabled = false; unlockNote(box, 'Network error. Please try again.', true); }
  }
  async function submitUnlockCode(box, inp, go) {
    go.disabled = true;
    try {
      const r = await fetch('/api/account/unlock-verify', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({token:sessionToken(), otp_code:inp.value})});
      const d = await r.json();
      if (d.success) { showPaymentResult(d.message + (d.reference ? ' (Reference ' + d.reference + ')' : ''), 'unlocked'); refreshSecurityBadge(); return; }
      go.disabled = false; unlockNote(box, d.error || 'Could not verify the code.', true);
    } catch (e) { go.disabled = false; unlockNote(box, 'Network error. Please try again.', true); }
  }
  function unlockNote(box, text, isError) {
    let n = box.querySelector('.unlock-note');
    if (!n) { n = document.createElement('div'); n.className = 'unlock-note'; box.appendChild(n); }
    n.textContent = text; n.style.color = isError ? '#b42318' : '#555';
  }
  function setStripeError(text) { if ($('stripe-card-errors')) $('stripe-card-errors').textContent = text || ''; }
  function sessionToken() { return localStorage.getItem('tv_session_token') || ''; }
  function idempotencyKey() { return 'pay-' + Date.now() + '-' + Math.random().toString(36).slice(2); }
  function digits(v) { return String(v || '').replace(/\D/g, ''); }

  // A random id kept in this browser (an extra fraud signal: many cards / accounts from one device). Not a login, not personal details.
  function deviceId() {
    try {
      let id = localStorage.getItem('tv_device_id');
      if (!id || !/^[A-Za-z0-9_-]{16,64}$/.test(id)) {
        id = (window.crypto && crypto.randomUUID) ? crypto.randomUUID() : Array.from({length: 32}, () => Math.floor(Math.random() * 16).toString(16)).join('');
        localStorage.setItem('tv_device_id', id);
      }
      return id;
    } catch (e) { return ''; }
  }

  async function api(path, body) {
    body = Object.assign({}, body || {});
    if (path.indexOf('/api/payments/') === 0) body.device_id = deviceId();
    const r = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
    const data = await r.json().catch(() => ({}));
    if (!r.ok || data.success === false) { const e = new Error(data.error || ('HTTP ' + r.status)); e.data = data; throw e; }
    return data;
  }

  async function initPaymentCheckout() {
    if (paymentMode) return;
    try {
      const cfgRes = await fetch('/api/payments/config');
      const cfg = await cfgRes.json();
      if (!cfgRes.ok || !cfg.mode) throw new Error(cfg.error || 'Payment provider configuration is unavailable.');
      paymentMode = cfg.mode;
      const stripeFields = $('stripe-payment-fields');
      const localFields = $('local-payment-fields');
      const note = $('payment-mode-note')?.querySelector('span');
      if (paymentMode === 'local_test') {
        stripeFields?.classList.add('hidden');
        localFields?.classList.remove('hidden');
        if (note) note.textContent = 'Development test provider only. Card details stay in this browser; TradeVerify receives only an opaque test token/fingerprint, the card\u2019s first 6 and last 4 digits (not enough to make a payment) and a random device id. No real payment is processed.';
        const testCfg = await fetch('/api/payments/local/test-config').then(r => r.json());
        labEnabled = !!testCfg.test_lab;
        if (labEnabled) $('open-fraud-lab')?.classList.remove('hidden');
        if (!testCfg.success) throw new Error(testCfg.error || 'Local test provider configuration failed.');
        if ($('local-test-hint')) {
          $('local-test-hint').textContent = testCfg.provider_outcome === 'approve_by_card'
            ? `Development provider: ONLY cards ending in ${(testCfg.approve_suffixes || []).join(', ')} are APPROVED (and mark the invoice paid). Any other card is DECLINED.`
            : testCfg.provider_outcome === 'by_card'
            ? `Development provider: cards ending in ${(testCfg.decline_suffixes || []).join(', ')} are DECLINED. Any other card is APPROVED and marks the invoice paid${labEnabled ? ' (use Reset in the Fraud Test Lab to test again)' : ''}.`
            : `Development provider outcome: ${String(testCfg.provider_outcome || 'authorized').toUpperCase()} \u2022 Any card-like test number can be entered. No card number is hard-coded.`;
        }
        await loadInvoice();
        return;
      }
      if (!window.Stripe) throw new Error('Stripe.js could not be loaded. Check internet access and retry.');
      const stripeCfgRes = await fetch('/api/payments/stripe/config');
      const stripeCfg = await stripeCfgRes.json();
      if (!stripeCfgRes.ok || !stripeCfg.publishable_key) throw new Error(stripeCfg.error || 'Stripe publishable key is not configured on the server.');
      stripe = Stripe(stripeCfg.publishable_key);
      stripeCard = stripe.elements().create('card', {hidePostalCode:false, style:{base:{fontSize:'16px',color:'#171717',fontFamily:'Inter, Arial, sans-serif','::placeholder':{color:'#8b8b8b'}},invalid:{color:'#b42318'}}});
      stripeCard.mount('#stripe-card-element');
      stripeCard.on('change', (event) => setStripeError(event.error ? event.error.message : ''));
      stripeReady = true;
      if (note) note.textContent = 'Stripe securely collects card details in hosted Elements. TradeVerify receives only a Stripe PaymentMethod ID and provider fingerprint for fraud screening; raw card data never reaches this server.';
      await loadInvoice();
    } catch (err) {
      showPaymentResult('Payment setup error: ' + err.message, 'error');
    }
  }

  async function loadInvoice() {
    const ref = ($('pf-ref-input')?.value || '').trim();
    if (!ref) return;
    try {
      const r = await fetch('/api/payments/invoice?ref=' + encodeURIComponent(ref));
      const data = await r.json();
      if (!r.ok || !data.success) throw new Error(data.error || 'Invoice lookup failed.');
      $('pf-ref').textContent = data.invoice.ref;
      $('pf-amount-display').textContent = data.invoice.display_amount;
    } catch (err) { showPaymentResult(err.message, 'error'); }
  }

  function fieldError(id, inputId, msg) {
    if ($(id)) $(id).textContent = msg || '';
    $(inputId)?.classList.toggle('invalid', !!msg);
    return !!msg;
  }
  function validateLocalCard() {
    const card = digits($('local-card-number')?.value);
    const expiry = digits($('local-expiry')?.value);
    const cvv = digits($('local-cvv')?.value);
    let bad = false;
    bad = fieldError('err-card', 'local-card-number', (card.length < 12 || card.length > 19) ? 'Enter a 12\u201319 digit card number.' : '') || bad;
    let expMsg = '';
    if (expiry.length !== 4) expMsg = 'Enter expiry as MM/YY.';
    else {
      const month = Number(expiry.slice(0,2)); const year = 2000 + Number(expiry.slice(2));
      const now = new Date();
      if (month < 1 || month > 12) expMsg = 'Month must be 01\u201312.';
      else if (new Date(year, month, 0) < new Date(now.getFullYear(), now.getMonth(), 1)) expMsg = 'Card has expired.';
    }
    bad = fieldError('err-expiry', 'local-expiry', expMsg) || bad;
    bad = fieldError('err-cvv', 'local-cvv', (cvv.length < 3 || cvv.length > 4) ? '3\u20134 digits.' : '') || bad;
    if (bad) throw new Error('Please fix the highlighted card fields.');
    return card;
  }

  async function localFingerprint(card) {
    const bytes = new TextEncoder().encode(card);
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return 'local_fp_' + Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2,'0')).join('').slice(0,32);
  }


  // Development only: stands in for the card network's answer. Security code 000 or postcode 00000 = "no match"; empty postcode = not checked.
  function simulatedChecks() {
    const cvv = digits($('local-cvv')?.value);
    const zip = ($('local-postcode')?.value || '').trim();
    return {cvc: cvv === '000' ? 'fail' : 'pass', postcode: !zip ? 'unchecked' : (/^0+$/.test(zip) ? 'fail' : 'pass')};
  }

  async function submitLocalPayment(ref, idem) {
    const card = validateLocalCard();
    const fingerprint = await localFingerprint(card);
    const token = 'local_pm_' + fingerprint.replace('local_fp_', '');
    const created = await api('/api/payments/local/create-intent', {token:sessionToken(), session_id:checkoutSession, invoice_ref:ref, idempotency_key:idem});
    paymentIntentId = created.payment_intent_id;
    const pre = await api('/api/payments/local/precheck', {token:sessionToken(), session_id:checkoutSession, payment_intent_id:paymentIntentId, payment_method_token:token, payment_method_fingerprint:fingerprint, card_last4:card.slice(-4), card_bin:card.slice(0, 6), simulated_checks:simulatedChecks(), idempotency_key:idem});
    if (pre.blocked) {
      showBlocked(pre);
      return;
    }
    const confirmed = await api('/api/payments/local/confirm', {token:sessionToken(), session_id:checkoutSession, payment_intent_id:paymentIntentId});
    if (confirmed.status === 'blocked' || confirmed.blocked_after_outcome) {
      showBlocked(confirmed, ' TradeVerify has suspended this payment session.');
    } else if (confirmed.status === 'succeeded') {
      showPaymentResult('Payment successful \u2014 TradeVerify allowed the transaction. Development provider only; no real money was moved.', 'ok');
    } else {
      const left = (confirmed.carding_audit || {}).attempts_remaining;
      const warn = (typeof left === 'number' && left > 0)
        ? ' You have ' + left + ' attempt' + (left === 1 ? '' : 's') + ' left with this card before payments are paused for security.'
        : '';
      showPaymentResult('Payment declined. Please check your card details and try again.' + warn, 'declined');
    }
  }

  // Accidental double-click guard (live/Stripe mode only): a second click while a payment is in flight, or within
  // 1.2 s of the previous one, is ignored in the browser so it never reaches the server and never counts as a bot strike.
  let payInFlight = false, lastPaySubmitAt = 0;
  window.submitIntegratedPayment = async function () {
    // The guard protects real customers. In the development test provider it is OFF, so the
    // fast-click (Problem 4) warning/block can be tried by hand on this page.
    const guardOn = paymentMode !== 'local_test';
    if (guardOn && (payInFlight || (Date.now() - lastPaySubmitAt) < 1200)) return;
    payInFlight = true; lastPaySubmitAt = Date.now();
    try { await runIntegratedPayment(); } finally { payInFlight = false; lastPaySubmitAt = Date.now(); }
  };
  async function runIntegratedPayment() {
    const ref = ($('pf-ref-input')?.value || '').trim();
    if (!ref) { showPaymentResult('Enter an invoice / shipment reference.', 'error'); return; }
    const btn = $('pf-pay'); btn.disabled = true; btn.classList.add('processing'); btn.innerHTML = '<span class="mini-spinner"></span> Screening payment...';
    setStripeError('');
    try {
      const idem = idempotencyKey();
      if (paymentMode === 'local_test') {
        await submitLocalPayment(ref, idem);
      } else {
        if (!stripeReady || !stripeCard) throw new Error('Secure Stripe payment field is still loading. Please wait a moment.');
        const created = await api('/api/payments/create-intent', {token:sessionToken(), session_id:checkoutSession, invoice_ref:ref, idempotency_key:idem});
        paymentIntentId = created.payment_intent_id; paymentClientSecret = created.client_secret;
        const pmResult = await stripe.createPaymentMethod({type:'card', card:stripeCard});
        if (pmResult.error) throw new Error(pmResult.error.message);
        const paymentMethodId = pmResult.paymentMethod.id;
        const pre = await api('/api/payments/precheck', {token:sessionToken(), session_id:checkoutSession, payment_intent_id:paymentIntentId, payment_method_id:paymentMethodId, idempotency_key:idem});
        if (pre.blocked) { showBlocked(pre); return; }
        const confirmed = await api('/api/payments/confirm', {token:sessionToken(), session_id:checkoutSession, payment_intent_id:paymentIntentId, payment_method_id:paymentMethodId, idempotency_key:idem, force_step_up:!!pre.step_up_required});
        if (confirmed.status === 'requires_action') {
          const action = await stripe.handleCardAction(confirmed.client_secret);
          if (action.error) throw new Error(action.error.message);
          const completed = await api('/api/payments/complete-after-action', {token:sessionToken(), payment_intent_id:paymentIntentId, idempotency_key:idem});
          showPaymentResult(completed.status === 'succeeded' ? 'Payment authenticated and authorized. Final invoice status is confirmed by Stripe webhook.' : 'Additional authentication completed; Stripe status is ' + completed.status + '.', completed.status === 'succeeded' ? 'ok' : 'stepup');
        } else if (confirmed.status === 'succeeded') showPaymentResult('Payment authorized in Stripe test mode. Final invoice status is confirmed by the Stripe webhook.', 'ok');
        else if (confirmed.status === 'requires_payment_method') showPaymentResult('Payment declined. The failed attempt has been recorded for fraud monitoring.', 'declined');
        else showPaymentResult('Stripe payment status: ' + confirmed.status, 'info');
      }
    } catch (err) {
      if (err.data && err.data.captcha_required) { showCaptchaChallenge(err.data); return; }
      if (err.data && err.data.slow_down) { showPaymentResult('Please slow down \u2014 payments are being submitted faster than normal. Wait a few seconds, then try again. If it happens again, this account will be blocked.', 'stepup'); return; }
      if (err.data && err.data.block_kind === 'bot') { showPaymentResult(BOT_ALERT_TEXT, 'botalert'); return; }
      const paid = /already been paid/i.test(err.message || '');
      showPaymentResult(paid
        ? 'This invoice is already paid, so no new payment attempt was made.' + (labEnabled ? ' To test again, open the Fraud Test Lab and click "Reset test invoice and blocks". To test failed payments, use any card that does not end in 0002.' : '')
        : 'Payment processing error: ' + err.message, paid ? 'stepup' : 'error');
    }
    finally { btn.disabled = false; btn.classList.remove('processing'); btn.innerHTML = '<i data-lucide="lock-keyhole"></i> Pay Securely'; if (window.lucide) lucide.createIcons(); }
  }

  async function testFire(session, fp, outcome) {
    const auth = sessionToken();
    const r = await fetch('/api/admin/fraud-test-event', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session_id:session,payment_method_fingerprint:fp,token:auth,outcome})});
    return r.json();
  }
  function labLine(i, d) {
    const bot = d.bot_audit || {}, card = d.carding_audit || {}, risk = d.risk_audit || {};
    const gap = (bot.gap_ms === null || bot.gap_ms === undefined) ? '-' : bot.gap_ms + ' ms';
    // If the session was already frozen by another rule, the bot check only echoes that freeze; do not present it as a bot finding.
    const botText = (bot.status === 'BOT_RED_FLAG' && bot.gap_ms === null && card.status === 'CARDING_RED_FLAG') ? 'n/a (session already frozen)' : bot.status;
    const left = (typeof card.attempts_remaining === 'number') ? '  tries_left=' + card.attempts_remaining : '';
    const rate = (typeof bot.rate_count === 'number' && bot.rate_window_seconds) ? '  rate=' + bot.rate_count + '/' + bot.rate_window_seconds + 's' : '';
    return `Attempt ${i}: gap=${gap}  bot=${botText}${rate}  card=${card.status}${left}  risk=${risk.decision}/${risk.score}  ${d.blocked ? '-> BLOCKED' : ''}\n`;
  }
  function labLocked(d) {
    return d.success && d.blocked && (d.carding_audit || {}).active_block && (d.carding_audit || {}).failed_attempts === null;
  }
  function labBanner(text) {
    const el = $('botAlertBanner'); if (!el) return;
    el.textContent = text || ''; el.classList.toggle('hidden', !text);
  }
  window.runIntegratedReset = async function () {
    const out = $('integratedTestOutput'); labBanner('');
    try {
      const r = await fetch('/api/admin/fraud-test-reset', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({token:sessionToken()})});
      const d = await r.json();
      out.textContent = d.success ? 'Reset done: the invoice is unpaid again and every fraud block and counter is cleared.\nYou can test again.\n' : ('Reset failed: ' + (d.error || 'unknown error') + '\n');
    } catch (e) { out.textContent = 'Reset failed: ' + e.message + '\n'; }
  };
  window.runIntegratedBotTest = async function () {
    const out = $('integratedTestOutput'); const run = Date.now();
    const s = 'lab-bot-' + run, fp = 'lab_bot_fp_' + run;   // fresh session + card each run, so only the bot rule can fire
    labBanner('');
    out.textContent = 'Bot-speed test: successful payments sent 150 ms apart (a human cannot click this fast)...\n';
    for (let i = 1; i <= 6; i++) {
      const d = await testFire(s, fp, 'authorized');
      if (!d.success) { out.textContent += 'Test could not run: ' + (d.error || 'unknown error') + '\n'; return; }
      if (i === 1 && labLocked(d)) { out.textContent += 'This account is already locked from an earlier test.\nClear it in Admin (or restart the server), then run again.\n'; return; }
      out.textContent += labLine(i, d);
      if (d.bot_audit?.status === 'SUSPECT') out.textContent += '   -> WARNING: slow down (a repeat blocks the account)\n';
      if (d.bot_audit?.status === 'BOT_RED_FLAG') {
        labBanner(d.bot_audit.alert || BOT_ALERT_TEXT);   // shown the moment the speed is detected
        out.textContent += '\nRESULT: payment speed was faster than a human can manage, so the account was blocked right then.\nOpen the Admin panel below to see the blocked account and unblock it.\n';
        return;
      }
      if (d.blocked) { out.textContent += '\nBlocked by: ' + (d.risk_audit?.reasons || []).join('; ') + '\n'; return; }
      await new Promise(r => setTimeout(r, 150));
    }
    out.textContent += '\nRESULT: no bot block. Check that the bot policy values in fraud_policy.json are unchanged.\n';
  };
  async function labRun(out, title, steps, gapMs, onDone) {
    labBanner('');
    const run = Date.now(); const s = 'lab-' + run;
    out.textContent = title + '\n';
    for (let i = 0; i < steps.length; i++) {
      const d = await testFire(s, steps[i].fp(run), steps[i].outcome);
      if (!d.success) { out.textContent += 'Test could not run: ' + (d.error || 'unknown error') + '\n'; return; }
      if (i === 0 && labLocked(d)) { out.textContent += 'This account is already locked from an earlier test.\nClear it in Admin (or restart the server), then run again.\n'; return; }
      out.textContent += `[${steps[i].outcome.toUpperCase()}] ` + labLine(i + 1, d);
      if (d.blocked) { out.textContent += onDone(true, i + 1); return; }
      if (i < steps.length - 1) await new Promise(r => setTimeout(r, gapMs));
    }
    out.textContent += onDone(false, steps.length);
  }
  window.runIntegratedCardingTest = function () {
    const same = run => 'lab_stolen_card_' + run;
    return labRun($('integratedTestOutput'), 'Problem 3: a stolen card is tried 4 times back to back, and every attempt fails (1.5 s apart, human pace)...',
      [1, 2, 3, 4].map(() => ({fp: same, outcome: 'declined'})), 1500,
      (blocked, n) => blocked ? `\nRESULT: blocked on failure #${n}. Back-to-back card failures detected, so the account was blocked.\nOpen the Admin panel to see it and unblock it.\n` : '\nRESULT: no block (unexpected).\n');
  };
  window.runIntegratedSweepTest = function () {
    const mk = k => run => 'lab_sweep_' + run + '_' + k;
    return labRun($('integratedTestOutput'), 'Problem 3 (sweep): 4 DIFFERENT stolen cards, all declined, 1.5 s apart...',
      [1, 2, 3, 4].map(k => ({fp: mk(k), outcome: 'declined'})), 1500,
      (blocked, n) => blocked ? `\nRESULT: blocked on failure #${n}. Card sweep detected, so the account was blocked.\nOpen the Admin panel to see it and unblock it.\n` : '\nRESULT: no block (unexpected).\n');
  };
  window.runIntegratedGenuineTest = function () {
    const same = run => 'lab_genuine_card_' + run;
    return labRun($('integratedTestOutput'), 'Genuine customer: fails 3 times, the 4th try goes through, then one more decline later...',
      [{fp: same, outcome: 'declined'}, {fp: same, outcome: 'declined'}, {fp: same, outcome: 'declined'}, {fp: same, outcome: 'authorized'}, {fp: same, outcome: 'declined'}], 1500,
      (blocked, n) => blocked
        ? `\nRESULT: blocked on attempt ${n} (unexpected for a genuine customer).\n`
        : '\nRESULT: never blocked. The successful payment ended the failure streak, so the last decline counts as a first failure again (tries_left back to 3).\n');
  };

  // Header badge: shows the account's REAL security state automatically (no manual simulator).
  async function refreshSecurityBadge() {
    const txt = $('liveSecurityText'), dot = $('scoutStatusDot'), sel = $('scoutScenarioSelect');
    const tok = sessionToken();
    if (!txt || !tok) return;
    try {
      const r = await fetch('/api/account/security-status', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({token:tok})});
      const d = await r.json();
      if (!d.success) return;
      txt.textContent = d.label; txt.title = (d.details || '') + (d.reference && !(d.details||'').includes(d.reference) ? ' Reference: ' + d.reference : '');
      if (dot) dot.className = 'scout-dot ' + (d.state === 'blocked' ? 'red' : d.state === 'warning' ? 'amber' : 'green');
      if (sel) sel.style.display = d.test_lab ? '' : 'none';   // the manual simulator only shows in the demo lab mode
    } catch (e) { /* server briefly unreachable: keep the last state */ }
  }
  setTimeout(refreshSecurityBadge, 400);
  setInterval(refreshSecurityBadge, 3000);

  document.addEventListener('keydown', (e) => { if(e.key==='Escape'){ closePaymentDrawer(); closeFraudTestDrawer(); } });
  const requested = new URLSearchParams(window.location.search).get('open');
  if (requested === 'payment') setTimeout(openPaymentDrawer, 120);
  if (requested === 'fraud-test') setTimeout(openFraudTestDrawer, 120);
  document.addEventListener('click', (e) => { if(e.target.classList.contains('drawer-overlay')) { e.target.classList.add('hidden'); e.target.setAttribute('aria-hidden','true'); document.body.classList.remove('drawer-open'); } });
  document.addEventListener('DOMContentLoaded', () => { if ($('paymentDrawer') && !$('paymentDrawer').classList.contains('hidden')) initStripeCheckout(); });
  // ---- Live card formatting + brand badge ----
  function cardBrand(n) {
    if (/^4/.test(n)) return 'VISA';
    if (/^(5[1-5]|2[2-7])/.test(n)) return 'MASTERCARD';
    if (/^3[47]/.test(n)) return 'AMEX';
    if (/^(60|65|81|82|508)/.test(n)) return 'RUPAY';
    return '';
  }
  document.addEventListener('input', (e) => {
    const t = e.target;
    if (t.id === 'local-card-number') {
      const d = digits(t.value).slice(0, 19);
      t.value = d.replace(/(.{4})/g, '$1 ').trim();
      const b = cardBrand(d), el = $('card-brand');
      if (el) { el.textContent = b; el.classList.toggle('show', !!b); }
      fieldError('err-card', 'local-card-number', '');
    } else if (t.id === 'local-expiry') {
      let d = digits(t.value).slice(0, 4);
      t.value = d.length > 2 ? d.slice(0, 2) + ' / ' + d.slice(2) : d;
      fieldError('err-expiry', 'local-expiry', '');
    } else if (t.id === 'local-cvv') {
      t.value = digits(t.value).slice(0, 4);
      fieldError('err-cvv', 'local-cvv', '');
    }
  });

  // ---- Receivables (exporter view) ----
  let rcTimer = null;
  const PAID = /paid|succeeded|authori[sz]ed|captured|settled/i, HELD = /block|hold|review/i, FAILED = /fail|declin|cancel/i;
  function renderReceivable(inv) {
    const st = String(inv.status || 'open');
    const kind = PAID.test(st) ? 'paid' : HELD.test(st) ? 'held' : FAILED.test(st) ? 'failed' : 'open';
    $('rc-ref').textContent = inv.ref; $('rc-amount').textContent = inv.display_amount;
    const badge = $('rc-status');
    badge.className = 'rc-badge ' + kind;
    badge.textContent = ({paid:'Paid', held:'Held for review', failed:'Payment failed', open:'Awaiting payment'})[kind];
    const steps = {issued:'done', initiated:'', screened:'', settled:''};
    if (kind === 'paid') { steps.initiated = steps.screened = steps.settled = 'done'; }
    else if (kind === 'held') { steps.initiated = 'done'; steps.screened = 'bad'; }
    else if (kind === 'failed') { steps.initiated = 'done'; steps.screened = 'done'; steps.settled = 'bad'; }
    else { steps.initiated = 'active'; }
    document.querySelectorAll('#rc-timeline li').forEach(li => { li.className = steps[li.dataset.step] || ''; });
    const err = $('rc-error'); if (err) err.className = 'payment-result';
  }
  async function loadReceivable() {
    const drawer = $('receivablesDrawer');
    if (!drawer || drawer.classList.contains('hidden')) { clearInterval(rcTimer); rcTimer = null; return; }
    const ref = ($('rc-ref-input')?.value || '').trim(); if (!ref) return;
    try {
      const r = await fetch('/api/payments/invoice?ref=' + encodeURIComponent(ref));
      const data = await r.json();
      if (!r.ok || !data.success) throw new Error(data.error || 'Invoice lookup failed.');
      renderReceivable(data.invoice);
    } catch (err) {
      const el = $('rc-error'); if (el) { el.className = 'payment-result error'; el.innerHTML = ''; const m = document.createElement('div'); m.textContent = err.message; el.appendChild(m); }
    }
  }
  window.openReceivablesDrawer = function () {
    setDrawer('receivablesDrawer', true);
    loadReceivable();
    clearInterval(rcTimer); rcTimer = setInterval(loadReceivable, 5000);
  };
  window.closeReceivablesDrawer = function () { setDrawer('receivablesDrawer', false); clearInterval(rcTimer); rcTimer = null; };
  document.addEventListener('change', (e) => { if (e.target.id === 'rc-ref-input') loadReceivable(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeReceivablesDrawer(); });
  if (new URLSearchParams(window.location.search).get('open') === 'receivables') setTimeout(openReceivablesDrawer, 120);
})();
