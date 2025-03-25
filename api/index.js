const express = require('express');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configure file uploads
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 50 * 1024 * 1024 },
});

// Initialize database
let db;
(async () => {
  db = await open({
    filename: './chattg.db',
    driver: sqlite3.Database,
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      display_name TEXT,
      bio TEXT,
      avatar TEXT,
      is_admin BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      content TEXT,
      user_id INTEGER,
      file_url TEXT,
      file_type TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER,
      expires_at DATETIME,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  const adminExists = await db.get("SELECT id FROM users WHERE is_admin = 1");
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash("admin123", 10);
    await db.run(
      "INSERT INTO users (username, password, display_name, is_admin) VALUES (?, ?, ?, ?)",
      "admin",
      hashedPassword,
      "Admin",
      1
    );
  }
})();

if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
app.use('/uploads', express.static('uploads'));

// Inline HTML and Frontend Logic
const getAppHtml = (page, sessionId = '') => `
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Chat App</title>
  <style>
    body { margin: 0; font-family: Arial, sans-serif; background: #f5f5f5; }
    .container { max-width: 800px; margin: 0 auto; padding: 20px; }
    .header { background: #0088cc; color: white; padding: 10px; display: flex; justify-content: space-between; }
    .messages { height: 400px; overflow-y: auto; background: #e5ddd5; padding: 10px; }
    .message { margin: 10px 0; padding: 10px; background: white; border-radius: 5px; max-width: 70%; }
    .message.sent { background: #dcf8c6; margin-left: auto; }
    .input-area { display: flex; margin-top: 10px; }
    .input-area input { flex: 1; padding: 10px; margin-right: 10px; border: 1px solid #ddd; border-radius: 5px; }
    .input-area button { padding: 10px; background: #0088cc; color: white; border: none; border-radius: 5px; }
    .auth { max-width: 400px; margin: 50px auto; padding: 20px; background: white; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
    .auth input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
    .auth button { width: 100%; padding: 10px; background: #0088cc; color: white; border: none; border-radius: 5px; }
    .error { color: red; text-align: center; }
  </style>
</head>
<body>
  ${page === 'login' ? `
    <div class="auth">
      <h1>Login</h1>
      <form id="login-form">
        <input type="text" id="username" placeholder="Username" required>
        <input type="password" id="password" placeholder="Password" required>
        <button type="submit">Login</button>
        <p>Don't have an account? <a href="/register">Register</a></p>
        <div id="error" class="error"></div>
      </form>
    </div>
  ` : page === 'register' ? `
    <div class="auth">
      <h1>Register</h1>
      <form id="register-form">
        <input type="text" id="username" placeholder="Username" required>
        <input type="password" id="password" placeholder="Password" required>
        <input type="text" id="display-name" placeholder="Display Name">
        <button type="submit">Register</button>
        <p>Already have an account? <a href="/login">Login</a></p>
        <div id="error" class="error"></div>
      </form>
    </div>
  ` : `
    <div class="container">
      <div class="header">
        <h1>Chat App</h1>
        <div>
          <span id="username-display"></span>
          <button id="logout-btn">Logout</button>
        </div>
      </div>
      <div class="messages" id="messages"></div>
      <div class="input-area">
        <input type="file" id="file-input" style="display: none;">
        <button id="attach-btn">📎</button>
        <input type="text" id="input" placeholder="Type a message...">
        <button id="send-btn">Send</button>
      </div>
    </div>
  `}
  <script>
    const sessionId = '${sessionId}';
    if (!sessionId && window.location.pathname !== '/login' && window.location.pathname !== '/register') {
      window.location.href = '/login';
    }

    // Auth Logic
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        try {
          const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
          });
          const data = await res.json();
          if (res.ok) {
            localStorage.setItem('sessionId', data.sessionId);
            window.location.href = '/';
          } else {
            document.getElementById('error').textContent = data.error;
          }
        } catch (err) {
          document.getElementById('error').textContent = 'Network error';
        }
      });
    }

    const registerForm = document.getElementById('register-form');
    if (registerForm) {
      registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const displayName = document.getElementById('display-name').value || username;
        try {
          const res = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, display_name: displayName })
          });
          const data = await res.json();
          if (res.ok) {
            window.location.href = '/login';
          } else {
            document.getElementById('error').textContent = data.error;
          }
        } catch (err) {
          document.getElementById('error').textContent = 'Network error';
        }
      });
    }

    // Chat Logic
    if (sessionId) {
      const messages = document.getElementById('messages');
      const input = document.getElementById('input');
      const sendBtn = document.getElementById('send-btn');
      const attachBtn = document.getElementById('attach-btn');
      const fileInput = document.getElementById('file-input');
      let currentFile = null;

      fetch('/api/user', { headers: { 'Authorization': sessionId } })
        .then(res => res.json())
        .then(user => {
          document.getElementById('username-display').textContent = user.display_name || user.username;
        });

      document.getElementById('logout-btn').addEventListener('click', async () => {
        await fetch('/api/logout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sessionId })
        });
        localStorage.removeItem('sessionId');
        window.location.href = '/login';
      });

      sendBtn.addEventListener('click', sendMessage);
      input.addEventListener('keypress', (e) => { if (e.key === 'Enter') sendMessage(); });
      attachBtn.addEventListener('click', () => fileInput.click());
      fileInput.addEventListener('change', handleFileUpload);

      loadMessages();

      async function sendMessage() {
        const content = input.value.trim();
        if (!content && !currentFile) return;
        const res = await fetch('/api/message', {
          method: 'POST',
          headers: { 'Authorization': sessionId, 'Content-Type': 'application/json' },
          body: JSON.stringify({ content, file: currentFile })
        });
        const msg = await res.json();
        if (res.ok) {
          addMessage(msg, true);
          input.value = '';
          currentFile = null;
          fileInput.value = '';
        }
      }

      async function handleFileUpload(e) {
        const file = e.target.files[0];
        if (!file) return;
        const formData = new FormData();
        formData.append('file', file);
        const res = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Authorization': sessionId },
          body: formData
        });
        const data = await res.json();
        if (res.ok) currentFile = { url: data.url, type: data.type, name: data.originalName };
      }

      function addMessage(msg, isSent) {
        const div = document.createElement('div');
        div.className = 'message' + (isSent ? ' sent' : '');
        div.innerHTML = \`
          <div style="font-size: 0.8em; color: #666;">
            \${msg.display_name || msg.username} - \${new Date(msg.created_at).toLocaleTimeString()}
          </div>
          <div>\${msg.content || ''}</div>
          \${msg.file_url ? (msg.file_type === 'image' ? 
            \`<img src="\${msg.file_url}" style="max-width: 100%;">\` : 
            \`<a href="\${msg.file_url}" target="_blank">\${msg.file_url.split('/').pop()}</a>\`) : ''}
        \`;
        messages.appendChild(div);
        messages.scrollTop = messages.scrollHeight;
      }

      async function loadMessages() {
        const res = await fetch('/api/messages', { headers: { 'Authorization': sessionId } });
        const msgs = await res.json();
        const userRes = await fetch('/api/user', { headers: { 'Authorization': sessionId } });
        const user = await userRes.json();
        msgs.forEach(msg => addMessage(msg, msg.user_id === user.id));
      }
    }
  </script>
</body>
</html>
`;

// Routes
app.get('/', async (req, res) => {
  const sessionId = req.headers.authorization || localStorage.getItem('sessionId');
  res.send(getAppHtml('chat', sessionId));
});

app.get('/login', (req, res) => res.send(getAppHtml('login')));
app.get('/register', (req, res) => res.send(getAppHtml('register')));

// API Routes
app.post('/api/register', async (req, res) => {
  const { username, password, display_name } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.run(
      "INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)",
      username,
      hashedPassword,
      display_name || username
    );
    res.json({ id: result.lastID, username });
  } catch (error) {
    res.status(error.errno === 19 ? 400 : 500).json({ error: error.errno === 19 ? "Username exists" : "Registration failed" });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.get("SELECT * FROM users WHERE username = ?", username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const sessionId = uuidv4();
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  await db.run(
    "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
    sessionId,
    user.id,
    expiresAt.toISOString()
  );
  res.json({ id: user.id, username: user.username, display_name: user.display_name, sessionId, isAdmin: user.is_admin });
});

app.post('/api/logout', async (req, res) => {
  const { sessionId } = req.body;
  await db.run("DELETE FROM sessions WHERE id = ?", sessionId);
  res.json({ success: true });
});

app.get('/api/user', async (req, res) => {
  const sessionId = req.headers.authorization;
  if (!sessionId) return res.status(401).json({ error: "Unauthorized" });
  const session = await db.get("SELECT * FROM sessions WHERE id = ? AND expires_at > datetime('now')", sessionId);
  if (!session) return res.status(401).json({ error: "Session expired" });
  const user = await db.get("SELECT id, username, display_name, bio, avatar FROM users WHERE id = ?", session.user_id);
  res.json(user);
});

app.post('/api/upload', upload.single('file'), async (req, res) => {
  const sessionId = req.headers.authorization;
  if (!sessionId || !await db.get("SELECT * FROM sessions WHERE id = ? AND expires_at > datetime('now')", sessionId)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  const ext = path.extname(req.file.originalname);
  const filename = `${uuidv4()}${ext}`;
  const filepath = path.join('uploads', filename);
  fs.renameSync(req.file.path, filepath);
  let fileType = "other";
  if (req.file.mimetype.startsWith("image/")) fileType = "image";
  else if (req.file.mimetype.startsWith("video/")) fileType = "video";
  res.json({ url: `/uploads/${filename}`, type: fileType, originalName: req.file.originalname });
});

app.post('/api/message', async (req, res) => {
  const sessionId = req.headers.authorization;
  const session = await db.get("SELECT * FROM sessions WHERE id = ? AND expires_at > datetime('now')", sessionId);
  if (!session) return res.status(401).json({ error: "Unauthorized" });
  const { content, file } = req.body;
  const result = await db.run(
    "INSERT INTO messages (content, user_id, file_url, file_type) VALUES (?, ?, ?, ?)",
    content,
    session.user_id,
    file?.url,
    file?.type
  );
  const message = await db.get(
    "SELECT m.*, u.username, u.display_name FROM messages m JOIN users u ON m.user_id = u.id WHERE m.id = ?",
    result.lastID
  );
  res.json(message);
});

app.get('/api/messages', async (req, res) => {
  const { before = '', limit = 50 } = req.query;
  const query = `SELECT m.*, u.username, u.display_name FROM messages m JOIN users u ON m.user_id = u.id
    ${before ? 'WHERE m.id < ?' : ''} ORDER BY m.id DESC LIMIT ?`;
  const params = before ? [before, limit] : [limit];
  const messages = await db.all(query, ...params);
  res.json(messages.reverse());
});

app.listen(3000, () => console.log('Server running at http://localhost:3000'));
