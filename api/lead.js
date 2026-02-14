const rateLimitStore = new Map();

const MAX_REQUESTS_PER_WINDOW = 5;
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;

function json(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(payload));
}

function cleanupRateLimit() {
  const now = Date.now();
  for (const [key, value] of rateLimitStore.entries()) {
    if (now - value.start > RATE_LIMIT_WINDOW_MS) {
      rateLimitStore.delete(key);
    }
  }
}

function isRateLimited(ip) {
  cleanupRateLimit();
  const now = Date.now();
  const row = rateLimitStore.get(ip);
  if (!row) {
    rateLimitStore.set(ip, { count: 1, start: now });
    return false;
  }

  if (now - row.start > RATE_LIMIT_WINDOW_MS) {
    rateLimitStore.set(ip, { count: 1, start: now });
    return false;
  }

  row.count += 1;
  rateLimitStore.set(ip, row);
  return row.count > MAX_REQUESTS_PER_WINDOW;
}

function getIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 1024 * 1024) {
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      try {
        const parsed = raw ? JSON.parse(raw) : {};
        resolve(parsed);
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function validateLead(payload) {
  const errors = [];

  const name = String(payload.name || '').trim();
  const company = String(payload.company || '').trim();
  const phone = String(payload.phone || '').trim();
  const email = String(payload.email || '').trim();
  const projectType = String(payload.projectType || '').trim();
  const message = String(payload.message || '').trim();
  const consent = Boolean(payload.consent);
  const website = String(payload.website || '').trim(); // honeypot
  const formStartedAt = Number(payload.formStartedAt || 0);

  if (!name || name.length < 2 || name.length > 80) {
    errors.push('Некорректное имя');
  }

  if (company.length > 120) {
    errors.push('Слишком длинное название компании');
  }

  if (!phone || phone.length < 7 || phone.length > 25) {
    errors.push('Некорректный телефон');
  }

  if (email && !/^\S+@\S+\.\S+$/.test(email)) {
    errors.push('Некорректный email');
  }

  if (!projectType || projectType.length > 120) {
    errors.push('Некорректный тип проекта');
  }

  if (!message || message.length < 10 || message.length > 2000) {
    errors.push('Некорректное описание задачи');
  }

  if (!consent) {
    errors.push('Требуется согласие на обработку данных');
  }

  if (website) {
    errors.push('Spam detected');
  }

  if (!formStartedAt || Date.now() - formStartedAt < 2500) {
    errors.push('Слишком быстрая отправка формы');
  }

  return {
    valid: errors.length === 0,
    errors,
    clean: {
      name,
      company,
      phone,
      email,
      projectType,
      message,
    },
  };
}

async function verifyTurnstile(token, ip) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) {
    return true;
  }

  if (!token) {
    return false;
  }

  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      secret,
      response: token,
      remoteip: ip,
    }),
  });

  const data = await response.json();
  return Boolean(data.success);
}

async function sendLeadEmail(lead) {
  const resendApiKey = process.env.RESEND_API_KEY;
  const toEmail = process.env.LEAD_TO_EMAIL;
  const fromEmail = process.env.LEAD_FROM_EMAIL;

  if (!resendApiKey || !toEmail || !fromEmail) {
    throw new Error('Email provider is not configured');
  }

  const html = `
    <h2>Новая заявка с сайта</h2>
    <p><b>Имя:</b> ${lead.name}</p>
    <p><b>Компания:</b> ${lead.company || '—'}</p>
    <p><b>Телефон:</b> ${lead.phone}</p>
    <p><b>Email:</b> ${lead.email || '—'}</p>
    <p><b>Тип проекта:</b> ${lead.projectType}</p>
    <p><b>Описание:</b><br/>${lead.message.replace(/\n/g, '<br/>')}</p>
    <hr/>
    <p style="font-size:12px;color:#666;">Источник: сайт Новый мир</p>
  `;

  const payload = {
    from: fromEmail,
    to: [toEmail],
    subject: `Новая заявка: ${lead.projectType}`,
    html,
  };

  if (lead.email) {
    payload.replyTo = lead.email;
  }

  const result = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${resendApiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!result.ok) {
    const text = await result.text();
    throw new Error(`Email send failed: ${text}`);
  }
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return json(res, 405, { ok: false, message: 'Method Not Allowed' });
  }

  const ip = getIp(req);
  if (isRateLimited(ip)) {
    return json(res, 429, { ok: false, message: 'Слишком много запросов. Повторите позже.' });
  }

  try {
    const payload = await parseBody(req);
    const { valid, errors, clean } = validateLead(payload);

    if (!valid) {
      return json(res, 400, { ok: false, message: errors[0] || 'Ошибка валидации' });
    }

    const turnstileToken = String(payload.turnstileToken || '');
    const turnstileOk = await verifyTurnstile(turnstileToken, ip);
    if (!turnstileOk) {
      return json(res, 400, { ok: false, message: 'Проверка антиспама не пройдена' });
    }

    await sendLeadEmail(clean);
    return json(res, 200, {
      ok: true,
      message: 'Спасибо за обращение. Менеджер свяжется с вами в ближайшее время.',
    });
  } catch (error) {
    return json(res, 500, { ok: false, message: 'Не удалось отправить заявку. Попробуйте позже.' });
  }
}
