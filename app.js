const express = require('express');
const fetch = require('node-fetch');
const Rcon = require('rcon-client').Rcon;
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const session = require('express-session');
require('dotenv').config();

const adminRouter = require('./adminRoutes.js');
const app = express();
const PORT = 3001;

// Настройки Free-Kassa
const FREE_KASSA_MERCHANT_ID = 'ВАШ_MERCHANT_ID';
const FREE_KASSA_SECRET = 'ВАШ_SECRET_KEY'; // Для коллбэков
const FREE_KASSA_SECRET_2 = 'ВАШ_SECOND_SECRET_KEY'; // Для подписи ссылок

app.use(express.static(path.join(__dirname, 'public')));
app.use('/data', express.static(path.join(__dirname, 'data')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 60 * 60 * 1000} // 1 час
}));

// --- Файлы данных ---
const serversFile = path.join(__dirname, 'data', 'servers.json');
const donateOptionsFile = path.join(__dirname, 'data', 'donateOptions.json');
const backgroundFile = path.join(__dirname, 'data', 'background.json');

// --- Админка ---
const ADMIN_LOGIN = process.env.ADMIN_LOGIN;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;

async function checkAdminCredentials(login, password) {
  if (login !== ADMIN_LOGIN) return false;
  const match = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  return match;
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    next();
  } else {
    res.redirect('/admin/login');
  }
}


app.use('/admin', adminRouter);

// --- Роуты админки ---
app.get('/admin/login', (req, res) => {
  res.render('admin/login', { error: null });
});

app.get('/admin/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/admin', requireAdmin, (req, res) => {
  const servers = loadJSON(serversFile);
  const donateOptions = loadJSON(donateOptionsFile);
  const background = loadJSON(backgroundFile);
  res.render('admin/dashboard', {
    servers,
    donateOptions,
    background
  });
});

app.post('/admin/set-background', requireAdmin, (req, res) => {
  const background = { image: req.body.image };
  saveJSON(backgroundFile, background);
  res.redirect('/admin');
});

app.post('/admin/add-server', requireAdmin, (req, res) => {
  const servers = loadJSON(serversFile);
  const { id, name, ip, avatar, rconHost, rconPort, rconPassword } = req.body;
  servers.push({ id, name, ip, avatar, rconHost, rconPort: parseInt(rconPort), rconPassword });
  saveJSON(serversFile, servers);
  res.redirect('/admin');
});

app.post('/admin/delete-server', requireAdmin, (req, res) => {
  let servers = loadJSON(serversFile);
  servers = servers.filter(s => s.id !== req.body.id);
  saveJSON(serversFile, servers);
  res.redirect('/admin');
});

app.post('/admin/add-donate', requireAdmin, (req, res) => {
  const donateOptions = loadJSON(donateOptionsFile);
  const { serverId, id, name, price, desc, rconCommand } = req.body;

  if (!donateOptions[serverId]) donateOptions[serverId] = [];
  donateOptions[serverId].push({
    id,
    name,
    price: parseFloat(price),
    desc,
    rconCommand
  });

  saveJSON(donateOptionsFile, donateOptions);
  res.redirect('/admin');
});

app.post('/admin/delete-donate', requireAdmin, (req, res) => {
  const donateOptions = loadJSON(donateOptionsFile);
  const { serverId, id } = req.body;

  if (donateOptions[serverId]) {
    donateOptions[serverId] = donateOptions[serverId].filter(d => d.id !== id);
    saveJSON(donateOptionsFile, donateOptions);
  }

  res.redirect('/admin');
});

// --- Главная страница ---
app.get('/', (req, res) => {
  background = loadJSON(backgroundFile);
  const rulesPath = path.join(__dirname, 'content', 'rules.html');
  const rulesContent = fs.existsSync(rulesPath) 
    ? fs.readFileSync(rulesPath, 'utf8')
    : '<p>Правила ещё не добавлены</p>';
  res.render('index', { content: rulesContent, title: 'Главная - MineOptima', bg: background });
});

// --- API: Статус серверов ---
app.get('/api/server-status', async (req, res) => {
  const servers = loadJSON(serversFile);
  const statuses = await Promise.all(servers.map(getServerStatus));
  res.json({ servers: statuses });
});

// --- API: Генерация подписи для ссылки ---
app.get('/api/generate-sign', (req, res) => {
  const { amount, orderId } = req.query;
  if (!amount || !orderId) return res.status(400).json({ error: 'Missing params' });

  const sign = crypto.createHash('md5')
    .update(`${FREE_KASSA_MERCHANT_ID}:${amount}:${FREE_KASSA_SECRET_2}:${orderId}`)
    .digest('hex');

  res.json({ merchantId: FREE_KASSA_MERCHANT_ID, sign });
});

// --- Коллбэк от Free-Kassa ---
app.post('/api/payment-callback', async (req, res) => {
  try {
    const { MERCHANT_ORDER_ID, AMOUNT, SIGN } = req.body;
    const purchaseId = MERCHANT_ORDER_ID;

    const expectedSign = crypto.createHash('sha256')
      .update(`${FREE_KASSA_MERCHANT_ID}:${AMOUNT}:${FREE_KASSA_SECRET}:${purchaseId}`)
      .digest('hex');

    if (expectedSign !== SIGN) {
      console.error('❌ Неверная подпись');
      updatePurchaseStatus(purchaseId, 'canceled');
      return res.status(400).send('Invalid signature');
    }

    const purchases = loadPurchases();
    const purchase = purchases.find(p => String(p.id) === String(purchaseId));
    if (!purchase) {
      updatePurchaseStatus(purchaseId, 'canceled');
      return res.status(400).send('Purchase not found');
    }

    const servers = loadJSON(serversFile);
    const srv = servers.find(s => s.id === purchase.serverId);
    const donateOptions = loadJSON(donateOptionsFile);
    const donateInfo = (donateOptions[purchase.serverId] || []).find(d => d.id === purchase.donateId);

    if (!srv || !donateInfo) {
      updatePurchaseStatus(purchaseId, 'canceled');
      return res.status(400).send('Invalid data');
    }

    if (parseFloat(AMOUNT) < donateInfo.price) {
      updatePurchaseStatus(purchaseId, 'canceled');
      return res.status(400).send('Insufficient amount');
    }

    const rcon = await Rcon.connect({
      host: srv.rconHost,
      port: srv.rconPort,
      password: srv.rconPassword
    });
    const cmd = donateInfo.rconCommand.replace('{player}', purchase.player);
    await rcon.send(cmd);
    rcon.end();

    updatePurchaseStatus(purchaseId, 'success');
    console.log(`✅ Выдан ${donateInfo.name} игроку ${purchase.player} на ${srv.name}`);
    res.send('YES');
  } catch (err) {
    console.error(err);
    if (req.body?.MERCHANT_ORDER_ID) {
      updatePurchaseStatus(req.body.MERCHANT_ORDER_ID, 'canceled');
    }
    res.status(500).send('Error');
  }
});

// Функция для обновления статуса
function updatePurchaseStatus(id, status) {
  const purchases = loadPurchases();
  const idx = purchases.findIndex(p => p.id == id);
  if (idx !== -1) {
    purchases[idx].status = status;
    purchases[idx].updatedAt = new Date().toISOString();
    saveJSON(purchasesFile, purchases);
  }
}

app.post('/create-purchase', (req, res) => {
  const purchases = loadPurchases();
  const id = Date.now();

  purchases.push({
    id,
    serverId: req.body.serverId,
    donateId: req.body.donateId,
    player: req.body.player,
    status: 'in-progress',
    createdAt: new Date().toISOString()
  });

  saveJSON(purchasesFile, purchases);

  req.session.lastPurchaseId = id;
  res.redirect(`/pay-with-frikassa?id=${id}`);
});

app.post('/admin/update-purchase-status', requireAdmin, (req, res) => {
  const { id, status } = req.body;

  if (!id || !status) {
    return res.status(400).json({ error: 'Неверные данные' });
  }

  const purchases = loadPurchases();
  const purchase = purchases.find(p => String(p.id) === String(id));
  if (!purchase) {
    return res.status(404).json({ error: 'Покупка не найдена' });
  }

  updatePurchaseStatus(id, status);
  res.json({ success: true });
});

function loadJSON(filePath) {
  if (fs.existsSync(filePath)) {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  }
  return {};
}

function saveJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

async function getServerStatus(server) {
  try {
    const response = await fetch(`https://api.mcsrvstat.us/2/${server.ip}`);
    const data = await response.json();
    return {
      id: server.id,
      name: server.name,
      ip: server.ip,
      avatar: server.avatar,
      online: data.online,
      players: data.players?.online || 0,
      maxPlayers: data.players?.max || 0
    };
  } catch (error) {
    console.error(`Ошибка статуса сервера ${server.name}:`, error);
    return {
      id: server.id,
      name: server.name,
      ip: server.ip,
      avatar: server.avatar,
      online: false,
      players: 0,
      maxPlayers: 0
    };
  }
}

// --- Файл покупок ---
const purchasesFile = path.join(__dirname, 'data', 'purchases.json');

function loadPurchases() {
  if (fs.existsSync(purchasesFile)) {
    return JSON.parse(fs.readFileSync(purchasesFile, 'utf8'));
  }
  return [];
}

// --- Страница покупок ---
app.get('/admin/purchases', requireAdmin, (req, res) => {
  const purchases = loadPurchases();
  res.render('admin/purchases', { purchases });
});


// Страница успешной оплаты
app.get('/payment-success', (req, res) => {
  res.render('payment-success', { title: 'Оплата успешна' });
});

// Страница ошибки оплаты
app.get('/payment-error', (req, res) => {
  if (req.session.lastPurchaseId) {
    updatePurchaseStatus(req.session.lastPurchaseId, 'canceled');
    delete req.session.lastPurchaseId;
  }
  res.render('payment-error', { title: 'Ошибка оплаты' });
});

// Проверка сайта для фрикассы
app.get('/fk-verify', (req, res) => {
  res.render('fk-verify', { title: 'Проверка' });
});


// --- Запуск сервера ---
app.listen(PORT, () => {
  console.log(`✅ Сервер запущен на http://localhost:${PORT}`);
});