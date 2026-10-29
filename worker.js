const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });

// أدوات الأمان
async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateToken() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getSessionUser(request, env) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/sost_session=([^;]+)/);
  if (!match) return null;
  const tokenHash = await sha256(match[1]);
  const { results } = await env.DB.prepare(
    `SELECT u.* FROM users u JOIN user_sessions s ON u.id = s.user_id WHERE s.session_hash = ? AND s.expires_at > ?`
  ).bind(tokenHash, Date.now()).all();
  return results.length ? results[0] : null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method;
    
    // CORS للسماح بالاتصال
    if (method === 'OPTIONS') return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': '*' } });

    // 1. فحص الصحة
    if (url.pathname === '/api/health') return json({ ok: true, database: Boolean(env.DB) });

    // 2. تسجيل حساب جديد
    if (url.pathname === '/api/auth/register' && method === 'POST') {
      const { username, password } = await request.json();
      if (!username || !password || password.length < 4) return json({ ok: false, error: 'بيانات غير صالحة' }, 400);

      const check = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
      if (check) return json({ ok: false, error: 'اسم المستخدم موجود مسبقاً' }, 400);

      const salt = generateToken().slice(0, 16);
      const pwdHash = await hashPassword(password, salt);
      const userId = crypto.randomUUID();

      await env.DB.prepare(
        `INSERT INTO users (id, username, password_hash, role, status, subscription, msgs_today, last_msg_date) 
         VALUES (?, ?, ?, 'user', 'active', 'free', 0, ?)`
      ).bind(userId, username, pwdHash + ':' + salt, new Date().toISOString().split('T')[0]).run();

      return json({ ok: true, message: 'تم إنشاء الحساب' });
    }

    // 3. تسجيل الدخول
    if (url.pathname === '/api/auth/login' && method === 'POST') {
      const { username, password } = await request.json();
      const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
      
      if (!user) return json({ ok: false, error: 'بيانات خاطئة' }, 401);
      if (user.banned && (user.ban_until > Date.now() || user.ban_until === 0)) return json({ ok: false, error: 'محظور', reason: user.ban_reason }, 403);

      const [hash, salt] = user.password_hash.split(':');
      const checkHash = await hashPassword(password, salt);
      if (checkHash !== hash) return json({ ok: false, error: 'بيانات خاطئة' }, 401);

      const rawToken = generateToken();
      const tokenHash = await sha256(rawToken);
      const expiresAt = Date.now() + (30 * 24 * 60 * 60 * 1000); // 30 يوم

      await env.DB.prepare('INSERT INTO user_sessions (id, user_id, session_hash, expires_at) VALUES (?, ?, ?, ?)')
        .bind(crypto.randomUUID(), user.id, tokenHash, expiresAt).run();

      const headers = new Headers();
      headers.append('Set-Cookie', `sost_session=${rawToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`);
      headers.append('Content-Type', 'application/json');
      
      return new Response(JSON.stringify({ ok: true, user: { username: user.username, role: user.role, subscription: user.subscription } }), { headers });
    }

    // 4. حالة المستخدم
    if (url.pathname === '/api/auth/me' && method === 'GET') {
      const user = await getSessionUser(request, env);
      if (!user) return json({ ok: false, error: 'غير مصرح' }, 401);
      return json({ ok: true, user: { username: user.username, role: user.role, subscription: user.subscription, msgs_today: user.msgs_today, banned: user.banned } });
    }

    // 5. جلب المحادثات
    if (url.pathname === '/api/chats' && method === 'GET') {
      const user = await getSessionUser(request, env);
      if (!user) return json({ ok: false, error: 'غير مصرح' }, 401);
      const { results } = await env.DB.prepare('SELECT * FROM conversations WHERE user_id = ? ORDER BY updated_at DESC').bind(user.id).all();
      return json({ ok: true, chats: results });
    }

    // 6. حفظ محادثة جديدة
    if (url.pathname === '/api/chats' && method === 'POST') {
      const user = await getSessionUser(request, env);
      if (!user) return json({ ok: false, error: 'غير مصرح' }, 401);
      
      if (user.banned && (user.ban_until > Date.now() || user.ban_until === 0)) return json({ ok: false, error: 'محظور' }, 403);
      
      // التحقق من الحدود
      const today = new Date().toISOString().split('T')[0];
      let msgsToday = user.msgs_today || 0;
      if (user.last_msg_date !== today) msgsToday = 0;

      if (user.subscription === 'free' && msgsToday >= 10) return json({ ok: false, error: 'وصلت للحد الأقصى' }, 429);

      const { title } = await request.json();
      const chatId = crypto.randomUUID();
      
      await env.DB.prepare('INSERT INTO conversations (id, user_id, title, updated_at) VALUES (?, ?, ?, ?)')
        .bind(chatId, user.id, title || 'محادثة جديدة', Date.now()).run();

      return json({ ok: true, id: chatId });
    }

    // 7. الرسائل (جلب وإرسال)
    if (url.pathname.startsWith('/api/chats/') && url.pathname.endsWith('/messages')) {
      const user = await getSessionUser(request, env);
      if (!user) return json({ ok: false, error: 'غير مصرح' }, 401);
      
      const chatId = url.pathname.split('/')[3];
      
      // التحقق من الملكية
      const chat = await env.DB.prepare('SELECT * FROM conversations WHERE id = ? AND user_id = ?').bind(chatId, user.id).first();
      if (!chat) return json({ ok: false, error: 'غير موجود' }, 404);

      if (method === 'GET') {
        const { results } = await env.DB.prepare('SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at ASC').bind(chatId).all();
        return json({ ok: true, messages: results });
      }

      if (method === 'POST') {
        const { role, content } = await request.json();
        if (role === 'user') {
           const today = new Date().toISOString().split('T')[0];
           let msgsToday = (user.last_msg_date === today) ? user.msgs_today : 0;
           msgsToday++;
           await env.DB.prepare('UPDATE users SET msgs_today = ?, last_msg_date = ?, total_msgs = total_msgs + 1 WHERE id = ?').bind(msgsToday, today, user.id).run();
        }

        await env.DB.prepare('INSERT INTO messages (id, conversation_id, role, content) VALUES (?, ?, ?, ?)')
          .bind(crypto.randomUUID(), chatId, role, content).run();
        
        await env.DB.prepare('UPDATE conversations SET updated_at = ? WHERE id = ?').bind(Date.now(), chatId).run();
        return json({ ok: true });
      }
    }

    // 8. الإدارة (للمشرف فقط)
    if (url.pathname.startsWith('/api/admin')) {
      const user = await getSessionUser(request, env);
      if (!user || user.role !== 'admin') return json({ ok: false, error: 'غير مصرح' }, 403);

      if (url.pathname === '/api/admin/users' && method === 'GET') {
        const { results } = await env.DB.prepare('SELECT id, username, subscription, total_msgs, banned FROM users').all();
        return json({ ok: true, users: results });
      }
      // يمكنك إضافة المزيد من مسارات الإدارة هنا
    }

    // 9. تمرير الذكاء الاصطناعي (الاحتفاظ بالكود الأصلي)
    if (url.pathname === '/api/chat' && method === 'POST') {
       // يمكنك هنا وضع كود الـ AI السابق أو تمريره
       return json({ ok: false, error: 'يجب ربط خدمة الذكاء الاصطناعي هنا' }, 501);
    }

    // 10. الملفات الثابتة
    if (env.ASSETS) return env.ASSETS.fetch(request);

    return new Response('Not Found', { status: 404 });
  }
};
