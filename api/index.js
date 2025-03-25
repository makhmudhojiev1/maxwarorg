const express = require('express');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configure file uploads with 80MB limit
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 80 * 1024 * 1024 },
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
      file_data TEXT,
      file_name TEXT,
      file_type TEXT,
      file_size INTEGER,
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

// HTML Templates
const loginPage = `
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - Chat App</title>
  <style>
    body { margin: 0; font-family: Arial, sans-serif; background: #f5f5f5; }
    .auth { max-width: 400px; margin: 50px auto; padding: 20px; background: white; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
    .auth input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
    .auth button { width: 100%; padding: 10px; background: #0088cc; color: white; border: none; border-radius: 5px; }
    .error { color: red; text-align: center; }
    .header { background: #0088cc; color: white; padding: 10px; text-align: center; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Chat App</h1>
  </div>
  <div class="auth">
    <h2>Login</h2>
    <form id="login-form">
      <input type="text" id="username" placeholder="Username" required>
      <input type="password" id="password" placeholder="Password" required>
      <button type="submit">Login</button>
      <p>Don't have an account? <a href="/register">Register</a></p>
      <div id="error" class="error"></div>
    </form>
  </div>
  <script>
    document.getElementById('login-form').addEventListener('submit', async (e) => {
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
  </script>
</body>
</html>
`;

const registerPage = `
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register - Chat App</title>
  <style>
    body { margin: 0; font-family: Arial, sans-serif; background: #f5f5f5; }
    .auth { max-width: 400px; margin: 50px auto; padding: 20px; background: white; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
    .auth input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
    .auth button { width: 100%; padding: 10px; background: #0088cc; color: white; border: none; border-radius: 5px; }
    .error { color: red; text-align: center; }
    .header { background: #0088cc; color: white; padding: 10px; text-align: center; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Chat App</h1>
  </div>
  <div class="auth">
    <h2>Register</h2>
    <form id="register-form">
      <input type="text" id="username" placeholder="Username" required>
      <input type="password" id="password" placeholder="Password" required>
      <input type="text" id="display-name" placeholder="Display Name">
      <button type="submit">Register</button>
      <p>Already have an account? <a href="/login">Login</a></p>
      <div id="error" class="error"></div>
    </form>
  </div>
  <script>
    document.getElementById('register-form').addEventListener('submit', async (e) => {
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
  </script>
</body>
</html>
`;

const chatPage = (sessionId) => `
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
    .file-input { display: none; }
    .file-info { margin-top: 5px; font-size: 0.8em; color: #666; }
  </style>
</head>
<body>
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
      <input type="file" id="file-input" class="file-input">
      <button id="attach-btn">📎</button>
      <input type="text" id="input" placeholder="Type a message...">
      <button id="send-btn">Send</button>
    </div>
    <div id="file-info" class="file-info"></div>
  </div>
  <script>
    const sessionId = '${sessionId}';
    if (!sessionId) window.location.href = '/login';

    // DOM elements
    const messagesEl = document.getElementById('messages');
    const inputEl = document.getElementById('input');
    const sendBtn = document.getElementById('send-btn');
    const attachBtn = document.getElementById('attach-btn');
    const fileInput = document.getElementById('file-input');
    const usernameDisplay = document.getElementById('username-display');
    const logoutBtn = document.getElementById('logout-btn');
    const fileInfoEl = document.getElementById('file-info');

    let currentFile = null;

    // Initialize
    fetchUser();
    loadMessages();
    setupEventListeners();

    async function fetchUser() {
      const res = await fetch('/api/user', { headers: { 'Authorization': sessionId } });
      const user = await res.json();
      usernameDisplay.textContent = user.display_name || user.username;
    }

    async function loadMessages() {
      const res = await fetch('/api/messages', { headers: { 'Authorization': sessionId } });
      const msgs = await res.json();
      const userRes = await fetch('/api/user', { headers: { 'Authorization': sessionId } });
      const user = await userRes.json();
      
      messagesEl.innerHTML = '';
      msgs.forEach(msg => addMessage(msg, msg.user_id === user.id));
    }

    function setupEventListeners() {
      sendBtn.addEventListener('click', sendMessage);
      inputEl.addEventListener('keypress', (e) => { if (e.key === 'Enter') sendMessage(); });
      attachBtn.addEventListener('click', () => fileInput.click());
      fileInput.addEventListener('change', handleFileUpload);
      logoutBtn.addEventListener('click', logout);
    }

    async function sendMessage() {
      const content = inputEl.value.trim();
      if (!content && !currentFile) return;
      
      const res = await fetch('/api/message', {
        method: 'POST',
        headers: { 
          'Authorization': sessionId, 
          'Content-Type': 'application/json' 
        },
        body: JSON.stringify({ 
          content,
          file_data: currentFile?.file_data,
          file_name: currentFile?.file_name,
          file_type: currentFile?.file_type,
          file_size: currentFile?.file_size
        })
      });
      
      if (res.ok) {
        inputEl.value = '';
        currentFile = null;
        fileInfoEl.textContent = '';
        loadMessages();
      }
    }

    async function handleFileUpload(e) {
      const file = e.target.files[0];
      if (!file) return;
      
      if (file.size > 80 * 1024 * 1024) {
        alert('File too large (max 80MB)');
        return;
      }
      
      const reader = new FileReader();
      reader.onload = async (event) => {
        const fileData = event.target.result.split(',')[1];
        currentFile = {
          file_data: fileData,
          file_name: file.name,
          file_type: file.type,
          file_size: file.size
        };
        fileInfoEl.textContent = \`File ready: \${file.name} (\${formatFileSize(file.size)})\`;
      };
      reader.readAsDataURL(file);
    }

    function addMessage(msg, isSent) {
      const div = document.createElement('div');
      div.className = 'message' + (isSent ? ' sent' : '');
      
      let fileContent = '';
      if (msg.file_data) {
        if (msg.file_type.startsWith('image/')) {
          fileContent = \`<img src="data:\${msg.file_type};base64,\${msg.file_data}" style="max-width: 100%;">\`;
        } else {
          fileContent = \`<a href="data:\${msg.file_type};base64,\${msg.file_data}" download="\${msg.file_name}">\${msg.file_name}</a>\`;
        }
      }
      
      div.innerHTML = \`
        <div style="font-size: 0.8em; color: #666;">
          \${msg.display_name || msg.username} - \${new Date(msg.created_at).toLocaleTimeString()}
        </div>
        <div>\${msg.content || ''}</div>
        \${fileContent}
      \`;
      messagesEl.appendChild(div);
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    async function logout() {
      await fetch('/api/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId })
      });
      localStorage.removeItem('sessionId');
      window.location.href = '/login';
    }

    function formatFileSize(bytes) {
      if (bytes < 1024) return bytes + ' bytes';
      else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
      else return (bytes / 1048576).toFixed(1) + ' MB';
    }
  </script>
</body>
</html>
`;

// Routes
app.get('/', async (req, res) => {
  const sessionId = req.headers.authorization || req.query.sessionId;
  if (!sessionId) return res.redirect('/login');
  
  const session = await db.get("SELECT * FROM sessions WHERE id = ? AND expires_at > datetime('now')", sessionId);
  if (!session) return res.redirect('/login');
  
  res.send(chatPage(sessionId));
});

app.get('/login', (req, res) => {
  res.send(loginPage);
});

app.get('/register', (req, res) => {
  res.send(registerPage);
});

// API Routes (same as before)
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
  
  if (req.file.size > 80 * 1024 * 1024) {
    return res.status(400).json({ error: "File too large (max 80MB)" });
  }

  const fileData = req.file.buffer.toString('base64');
  res.json({ 
    file_data: fileData,
    file_name: req.file.originalname,
    file_type: req.file.mimetype,
    file_size: req.file.size
  });
});

app.post('/api/message', async (req, res) => {
  const sessionId = req.headers.authorization;
  const session = await db.get("SELECT * FROM sessions WHERE id = ? AND expires_at > datetime('now')", sessionId);
  if (!session) return res.status(401).json({ error: "Unauthorized" });
  
  const { content, file_data, file_name, file_type, file_size } = req.body;
  
  if (file_size && file_size > 80 * 1024 * 1024) {
    return res.status(400).json({ error: "File too large (max 80MB)" });
  }

  const result = await db.run(
    "INSERT INTO messages (content, user_id, file_data, file_name, file_type, file_size) VALUES (?, ?, ?, ?, ?, ?)",
    content,
    session.user_id,
    file_data,
    file_name,
    file_type,
    file_size
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

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
