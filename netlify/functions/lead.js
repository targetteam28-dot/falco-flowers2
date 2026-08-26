// Netlify Function: /.netlify/functions/lead
// Приймає заявки з ЛЕНДИНГУ і з КВІЗУ (обидві форми POST-ять на /api/lead,
// редірект налаштований у netlify.toml). Для кожної заявки:
//   1) шле повідомлення в Telegram (головний канал — власник бачить ліда одразу);
//   2) відправляє подію Lead у Meta Conversions API (server-side, дублює Pixel,
//      дедуплікація через спільний event_id).
//
// СЕКРЕТИ НЕ ЗАШИТІ В КОД — тільки Environment Variables Netlify:
//   TELEGRAM_BOT_TOKEN   TELEGRAM_CHAT_ID
//   META_PIXEL_ID        META_ACCESS_TOKEN
//   ALLOWED_ORIGIN       (необов'язково; дефолт — flowers-falco2.netlify.app)
//   META_TEST_EVENT_CODE (необов'язково; тестовий режим CAPI)

const crypto = require('crypto');

// ── прості локи безпеки ─────────────────────────────────────────────
const RL = new Map();                 // rate-limit: ip -> [timestamps] (в межах теплого контейнера)
const RL_WINDOW = 60 * 1000;
const RL_MAX = 6;                      // не більше 6 заявок з IP за хвилину
const MIN_FILL_MS = 2500;             // швидше — це бот
const MAX_LEN = 200;                  // обрізка полів

function rateLimited(ip) {
  const now = Date.now();
  const arr = (RL.get(ip) || []).filter(t => now - t < RL_WINDOW);
  arr.push(now);
  RL.set(ip, arr);
  return arr.length > RL_MAX;
}

function originAllowed(headers) {
  const allowed = (process.env.ALLOWED_ORIGIN || 'https://flowers-falco2.netlify.app')
    .split(',').map(s => s.trim()).filter(Boolean);
  const origin = headers.origin || '';
  const referer = headers.referer || '';
  // Блокуємо тільки якщо Origin присутній і не в списку (крос-сайтне зловживання).
  if (origin) return allowed.includes(origin);
  if (referer) return allowed.some(a => referer.startsWith(a));
  return true; // ані origin, ані referer — не ламаємо легітимні кейси, ловлять інші локи
}

const clean = v => String(v == null ? '' : v).trim().slice(0, MAX_LEN);
const escHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function sha256(v) {
  return crypto.createHash('sha256').update(String(v).trim().toLowerCase()).digest('hex');
}
// нормалізація укр. телефону для CAPI (цифри, з кодом країни, без «+»)
function normPhone(contact) {
  let d = String(contact).replace(/\D/g, '');
  if (!d) return null;
  if (d.length === 10 && d.startsWith('0')) d = '38' + d;
  else if (d.length === 9) d = '380' + d;
  else if (d.length === 12 && d.startsWith('380')) { /* ok */ }
  if (d.length < 11) return null;      // схоже на @username, а не телефон
  return d;
}

exports.handler = async function (event) {
  const headers = event.headers || {};

  if (event.httpMethod !== 'POST') {
    return resp(405, { error: 'Method not allowed' });
  }
  if (!originAllowed(headers)) {
    return resp(403, { error: 'Forbidden origin' });
  }

  const ip = (headers['x-forwarded-for'] || headers['client-ip'] || '').split(',')[0].trim();
  if (ip && rateLimited(ip)) {
    return resp(429, { error: 'Too many requests' });
  }

  let body;
  try { body = JSON.parse(event.body); }
  catch { return resp(400, { error: 'Invalid JSON' }); }

  // ── антибот: honeypot + час заповнення ────────────────────────────
  // Ботам показуємо «успіх», щоб вони не підбирали обхід.
  if (clean(body.hp)) return resp(200, { ok: true });
  if (typeof body.t === 'number' && body.t < MIN_FILL_MS) return resp(200, { ok: true });

  const data = body.data || {};
  const name = clean(data.name);
  const contact = clean(data.contact);
  if (!name || !contact) return resp(400, { error: 'Missing required fields' });

  const isQuiz = !!body.quiz || body.source === 'quiz';

  const results = await Promise.allSettled([
    sendToTelegram({ name, contact, source: body.source, quiz: body.quiz, landing: data, isQuiz }),
    sendToMetaCAPI({ contact, body, headers })
  ]);

  const tgFailed = results[0].status === 'rejected';
  const capiFailed = results[1].status === 'rejected';
  if (tgFailed) console.error('Telegram error:', results[0].reason);
  if (capiFailed) console.error('Meta CAPI error:', results[1].reason);

  if (tgFailed) return resp(500, { ok: false, error: 'Failed to deliver lead' });
  return resp(200, { ok: true, capi_sent: !capiFailed });
};

function resp(code, obj) {
  return { statusCode: code, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(obj) };
}

async function sendToTelegram({ name, contact, source, quiz, landing, isQuiz }) {
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!botToken || !chatId) throw new Error('Telegram env vars not configured');

  let text;
  if (isQuiz && quiz) {
    const a = quiz.answers || {};
    const c = quiz.calc || {};
    const tools = Array.isArray(a.tools) ? a.tools.join(', ') : (a.tools || '—');
    text =
      `🧮 <b>Нова заявка з КВІЗУ (квітковий)</b>\n\n` +
      `👤 Ім'я: <b>${escHtml(name || '—')}</b>\n` +
      `📞 Контакт: <b>${escHtml(contact)}</b>\n` +
      `━━━━━━━━━━━━\n` +
      `📍 Місто: ${escHtml(a.geo || '—')}\n` +
      `💵 Чек: ${escHtml(a.check || '—')}\n` +
      `📅 Регулярність: ${escHtml(a.regularity || '—')}\n` +
      `🎬 Контент: ${escHtml(a.content || '—')}\n` +
      `💰 Оборот (А): ${escHtml(a.oborot || '—')}\n` +
      `🎯 Ціль на 6 міс (Б): ${escHtml(a.goal || '—')}\n` +
      `🧰 Інструменти: ${escHtml(tools)}\n` +
      `━━━━━━━━━━━━\n` +
      `📊 <b>Розрахунок:</b>\n` +
      `• Ціна заявки: ${escHtml(c.cpl || '—')}\n` +
      `• Ціна клієнта: ${escHtml(c.cpo || '—')}\n` +
      `• Бюджет: ${escHtml(c.budget || '—')}\n` +
      `• Прогноз обороту: ${escHtml(c.forecast || '—')}\n` +
      `• Оцінка: ${escHtml(String(c.score ?? '—'))}/10`;
  } else {
    text =
      `🌸 <b>Нова заявка з лендингу</b>\n\n` +
      `👤 Ім'я: <b>${escHtml(name || '—')}</b>\n` +
      `📞 Контакт: <b>${escHtml(contact)}</b>\n` +
      `💰 Оборот: ${escHtml(landing.turnover || '—')}\n` +
      `📊 Бюджет: ${escHtml(landing.budget || '—')}\n` +
      `📍 Джерело: ${escHtml(source || '—')}`;
  }

  const r = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true })
  });
  const json = await r.json();
  if (!json.ok) throw new Error('Telegram API error: ' + JSON.stringify(json));
  return json;
}

async function sendToMetaCAPI({ contact, body, headers }) {
  const pixelId = process.env.META_PIXEL_ID;
  const accessToken = process.env.META_ACCESS_TOKEN;
  if (!pixelId || !accessToken) throw new Error('Meta CAPI env vars not configured');

  const clientIp = (headers['x-forwarded-for'] || headers['client-ip'] || '').split(',')[0].trim();
  const userAgent = headers['user-agent'] || '';

  const user_data = { client_ip_address: clientIp, client_user_agent: userAgent };
  const phone = normPhone(contact);
  if (phone) user_data.ph = sha256(phone);
  if (body.fbp) user_data.fbp = body.fbp;
  if (body.fbc) user_data.fbc = body.fbc;

  const custom = body.quiz
    ? { source: body.source || 'quiz', ...(body.quiz.calc || {}) }
    : { turnover: (body.data && body.data.turnover) || '', budget: (body.data && body.data.budget) || '', source: body.source || '' };

  const payload = {
    data: [{
      event_name: 'Lead',
      event_time: Math.floor(Date.now() / 1000),
      event_id: body.event_id,
      event_source_url: body.event_source_url,
      action_source: 'website',
      user_data,
      custom_data: custom
    }]
  };
  if (process.env.META_TEST_EVENT_CODE) payload.test_event_code = process.env.META_TEST_EVENT_CODE;

  const r = await fetch(`https://graph.facebook.com/v19.0/${pixelId}/events?access_token=${accessToken}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const json = await r.json();
  if (json.error) throw new Error('Meta CAPI error: ' + JSON.stringify(json.error));
  return json;
}
