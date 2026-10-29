// ==========================================
// SOST AI - Cloudflare Worker Backend
// ==========================================

const json = (data, status = 200, extraHeaders = {}) => {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extraHeaders
    }
  });
};

// دالة مساعدة لإنشاء الهاش (PBKDF2)
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

function generateSalt() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');
}

// استخراج المستخدم من الكوكيز
async function getSessionUser(request, env) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/sost_session=([^;]+)/);
  if (!match) return null;
  
  const tokenHash = await sha256(match[1]);
  
  const { results } = await env.DB.prepare(
    `SELECT u.* FROM users u 
     JOIN user_sessions s ON u.id = s.user_id 
     WHERE s.session_hash = ? AND s.expires_at > ?`
  ).bind(tokenHash, Date.now()).all();
  
  return results.length ? results[0] : null;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method;

    // --- 1. APIs ---
    if (url.pathname.startsWith('/api/')) {

      // 1. فحص الصحة
      if (url.pathname === '/api/health') {
        return json({ ok: true, db: !!env.DB });
      }

      // 2. تسجيل حساب جديد
      if (url.pathname === '/api/auth/register' && method === 'POST') {
        const { username, password } = await request.json();
        if (!username || !password || username.length < 3) return json({ ok: false, error: 'بيانات غير صالحة' }, 400);

        const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
        if (existing) return json({ ok: false, error: 'اسم المستخدم موجود بالفعل' }, 400);

        const salt = generateSalt();
        const pwdHash = await hashPassword(password, salt);
        
        // دمج الملح مع الهاش
        const finalHash = `${salt}:${pwdHash}`;

        await env.DB.prepare(
          `INSERT INTO users (username, password_hash, role, status, created_at) VALUES (?, ?, 'user', 'active', ?)`
        ).bind(username, finalHash, Date.now()).run();

        return json({ ok: true, message: 'تم إنشاء الحساب بنجاح' });
      }

      // 3. تسجيل الدخول
      if (url.pathname === '/api/auth/login' && method === 'POST') {
        const { username, password } = await request.json();
        
        const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
        if (!user) return json({ ok: false, error: 'بيانات الدخول غير صحيحة' }, 401);
        
        if (user.status === 'banned') {
          return json({ ok: false, error: 'هذا الحساب محظور' }, 403);
        }

        const [salt, oldHash] = (user.password_hash || '').split(':');
        const verifyHash = await hashPassword(password, salt);
        
        if (verifyHash !== oldHash) return json({ ok: false, error: 'بيانات الدخول غير صحيحة' }, 401);

        // إنشاء جلسة جديدة
        const rawToken = crypto.randomUUID() + crypto.randomUUID();
        const sessionHash = await sha256(rawToken);
        const expiresAt = Date.now() + (30 * 24 * 60 * 60 * 1000); // 30 يوم

        await env.DB.prepare(
          `INSERT INTO user_sessions (user_id, session_hash, expires_at, created_at) VALUES (?, ?, ?, ?)`
        ).bind(user.id, sessionHash, expiresAt, Date.now()).run();

        const cookie = `sost_session=${rawToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`;
        
        return json({ ok: true, message: 'تم الدخول' }, 200, { 'Set-Cookie': cookie });
      }

      // 4. تسجيل الخروج
      if (url.pathname === '/api/auth/logout' && method === 'POST') {
        const cookieHeader = request.headers.get('Cookie') || '';
        const match = cookieHeader.match(/sost_session=([^;]+)/);
        if (match) {
          const sessionHash = await sha256(match[1]);
          await env.DB.prepare('DELETE FROM user_sessions WHERE session_hash = ?').bind(sessionHash).run();
        }
        return json({ ok: true }, 200, { 'Set-Cookie': 'sost_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0' });
      }

      // 5. جلب بيانات المستخدم الحالي
      if (url.pathname === '/api/auth/me' && method === 'GET') {
        const user = await getSessionUser(request, env);
        if (!user) return json({ ok: false, error: 'غير مصرح' }, 401);
        return json({ ok: true, user: { id: user.id, username: user.username, role: user.role, status: user.status } });
      }

      // --- جميع المسارات التالية تتطلب تسجيل الدخول ---
      const user = await getSessionUser(request, env);
      if (!user) return json({ ok: false, error: 'يجب تسجيل الدخول أولاً' }, 401);

      // 6. جلب المحادثات
      if (url.pathname === '/api/chats' && method === 'GET') {
        const { results } = await env.DB.prepare('SELECT id, title FROM conversations WHERE user_id = ? ORDER BY created_at DESC').bind(user.id).all();
        return json({ ok: true, chats: results });
      }

      // 7. جلب رسائل محادثة معينة
      if (url.pathname.startsWith('/api/chats/') && url.pathname.endsWith('/messages') && method === 'GET') {
        const chatId = url.pathname.split('/')[3];
        const chatOwner = await env.DB.prepare('SELECT id FROM conversations WHERE id = ? AND user_id = ?').bind(chatId, user.id).first();
        
        if (!chatOwner) return json({ ok: false, error: 'غير مصرح' }, 403);

        const { results } = await env.DB.prepare('SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY created_at ASC').bind(chatId).all();
        return json({ ok: true, messages: results });
      }

      // 8. إرسال رسالة والذكاء الاصطناعي (التحقق من الحدود هنا)
      if (url.pathname === '/api/chat' && method === 'POST') {
        const { conversationId, message } = await request.json();
        
        // التحقق من حدود الاشتراك (كمثال: 10 رسائل للمجاني)
        const sub = await env.DB.prepare('SELECT * FROM subscriptions WHERE user_id = ? AND status = "active" AND expires_at > ?').bind(user.id, Date.now()).first();
        let isPremium = !!sub;
        
        if (!isPremium) {
           const msgCount = await env.DB.prepare('SELECT COUNT(*) as c FROM messages m JOIN conversations c ON m.conversation_id = c.id WHERE c.user_id = ? AND m.role = "user"').bind(user.id).first();
           if (msgCount.c >= 10) {
             return json({ ok: false, error: 'وصلت للحد الأقصى للرسائل المجانية' }, 403);
           }
        }

        // حفظ المحادثة إذا كانت جديدة
        let chat = await env.DB.prepare('SELECT id FROM conversations WHERE id = ? AND user_id = ?').bind(conversationId, user.id).first();
        if (!chat) {
          await env.DB.prepare('INSERT INTO conversations (id, user_id, title, created_at) VALUES (?, ?, ?, ?)').bind(conversationId, user.id, message.slice(0, 30), Date.now()).run();
        }

        // حفظ رسالة المستخدم
        await env.DB.prepare('INSERT INTO messages (conversation_id, role, content, created_at) VALUES (?, "user", ?, ?)').bind(conversationId, message, Date.now()).run();

        // جلب سياق المحادثة السابقة
        const { results: history } = await env.DB.prepare('SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY created_at ASC LIMIT 10').bind(conversationId).all();
        
        let messages = history.map(m => ({ role: m.role, content: m.content }));

        // الاتصال بموديل الذكاء الاصطناعي (Pollinations AI كمثال مجاني)
        let reply = '';
        try {
            const aiRes = await fetch('https://text.pollinations.ai/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    messages: [
                        { role: 'system', content: 'أنت SOST AI، مساعد ذكي ومطور. أجب باللغة العربية بأسلوب واضح ومفيد.' },
                        ...messages
                    ],
                    model: 'openai'
                })
            });
            reply = await aiRes.text();
        } catch (e) {
            reply = "عذراً، حدث خطأ في الاتصال بمحرك الذكاء الاصطناعي.";
        }

        // حفظ رد الذكاء الاصطناعي
        await env.DB.prepare('INSERT INTO messages (conversation_id, role, content, created_at) VALUES (?, "assistant", ?, ?)').bind(conversationId, reply, Date.now()).run();

        return json({ ok: true, reply });
      }

      return json({ ok: false, error: 'API Route Not Found' }, 404);
    }

    // --- 2. الأصول الثابتة (HTML, CSS, JS) ---
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response('Not Found', { status: 404 });
  }
};
