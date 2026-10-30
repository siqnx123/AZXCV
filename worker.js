const json = (data, status = 200, extraHeaders = {}) => {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extraHeaders }
  });
};

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

    if (url.pathname === '/api/health') {
      return json({ ok: true, db: !!env.DB });
    }

    if (url.pathname.startsWith('/api/')) {
      if (!env.DB) return json({ ok: false, error: "Database missing" }, 500);

      // Register
      if (url.pathname === '/api/auth/register' && method === 'POST') {
        const { username, password } = await request.json();
        if (!username || !password) return json({ ok: false, error: 'بيانات ناقصة' }, 400);
        const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
        if (existing) return json({ ok: false, error: 'الاسم مسجل بالفعل' }, 400);
        
        const salt = generateSalt();
        const pwdHash = await hashPassword(password, salt);
        const finalHash = `${salt}:${pwdHash}`;
        
        await env.DB.prepare(`INSERT INTO users (username, password_hash, role, status, created_at) VALUES (?, ?, 'user', 'active', ?)`).bind(username, finalHash, Date.now()).run();
        return json({ ok: true, message: 'تم إنشاء الحساب' });
      }

      // Login
      if (url.pathname === '/api/auth/login' && method === 'POST') {
        const { username, password } = await request.json();
        const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
        if (!user) return json({ ok: false, error: 'بيانات خاطئة' }, 401);
        if (user.status === 'banned') return json({ ok: false, error: 'الحساب محظور' }, 403);
        
        const [salt, oldHash] = (user.password_hash || '').split(':');
        const verifyHash = await hashPassword(password, salt);
        if (verifyHash !== oldHash) return json({ ok: false, error: 'بيانات خاطئة' }, 401);

        const rawToken = crypto.randomUUID() + crypto.randomUUID();
        const sessionHash = await sha256(rawToken);
        const expiresAt = Date.now() + (30 * 24 * 60 * 60 * 1000);
        
        await env.DB.prepare(`INSERT INTO user_sessions (user_id, session_hash, expires_at, created_at) VALUES (?, ?, ?, ?)`).bind(user.id, sessionHash, expiresAt, Date.now()).run();
        
        const cookie = `sost_session=${rawToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`;
        return json({ ok: true }, 200, { 'Set-Cookie': cookie });
      }

      // Logout
      if (url.pathname === '/api/auth/logout' && method === 'POST') {
        const cookieHeader = request.headers.get('Cookie') || '';
        const match = cookieHeader.match(/sost_session=([^;]+)/);
        if (match) {
          const sessionHash = await sha256(match[1]);
          await env.DB.prepare('DELETE FROM user_sessions WHERE session_hash = ?').bind(sessionHash).run();
        }
        return json({ ok: true }, 200, { 'Set-Cookie': 'sost_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0' });
      }

      // Me
      if (url.pathname === '/api/auth/me' && method === 'GET') {
        const user = await getSessionUser(request, env);
        if (!user) return json({ ok: false }, 401);
        return json({ ok: true, user: { id: user.id, username: user.username, role: user.role, status: user.status } });
      }

      const user = await getSessionUser(request, env);
      if (!user) return json({ ok: false, error: 'يجب تسجيل الدخول' }, 401);

      // Get Chats
      if (url.pathname === '/api/chats' && method === 'GET') {
        const { results } = await env.DB.prepare('SELECT id, title FROM conversations WHERE user_id = ? ORDER BY created_at DESC').bind(user.id).all();
        return json({ ok: true, chats: results });
      }

      // Get Messages
      if (url.pathname.startsWith('/api/chats/') && url.pathname.endsWith('/messages') && method === 'GET') {
        const chatId = url.pathname.split('/')[3];
        const chatOwner = await env.DB.prepare('SELECT id FROM conversations WHERE id = ? AND user_id = ?').bind(chatId, user.id).first();
        if (!chatOwner) return json({ ok: false, error: 'غير مصرح' }, 403);
        const { results } = await env.DB.prepare('SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY created_at ASC').bind(chatId).all();
        return json({ ok: true, messages: results });
      }

      // Chat with AI
      if (url.pathname === '/api/chat' && method === 'POST') {
        const { conversationId, message } = await request.json();
        
        let chat = await env.DB.prepare('SELECT id FROM conversations WHERE id = ? AND user_id = ?').bind(conversationId, user.id).first();
        if (!chat) {
          await env.DB.prepare('INSERT INTO conversations (id, user_id, title, created_at) VALUES (?, ?, ?, ?)').bind(conversationId, user.id, message.slice(0, 30), Date.now()).run();
        }
        await env.DB.prepare('INSERT INTO messages (conversation_id, role, content, created_at) VALUES (?, "user", ?, ?)').bind(conversationId, message, Date.now()).run();

        let reply = '';
        try {
          // استخدام Pollinations API من الخادم لتجنب مشاكل الحد الأقصى للـ IP
          const aiRes = await fetch('https://text.pollinations.ai/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              messages: [
                { role: 'system', content: 'أنت SOST AI، مساعد ذكي ومطور. أجب باللغة العربية بأسلوب واضح ومفيد.' },
                { role: 'user', content: message }
              ],
              model: 'openai'
            })
          });
          reply = await aiRes.text();
        } catch (e) {
          reply = "عذراً، حدث خطأ في الاتصال بالذكاء الاصطناعي.";
        }

        await env.DB.prepare('INSERT INTO messages (conversation_id, role, content, created_at) VALUES (?, "assistant", ?, ?)').bind(conversationId, reply, Date.now()).run();
        return json({ ok: true, reply });
      }

      return json({ ok: false, error: 'API Not Found' }, 404);
    }

    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response('Not Found', { status: 404 });
  }
};
