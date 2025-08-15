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


const FREE_KASSA_MERCHANT_ID = process.env.FREE_KASSA_MERCHANT_ID;
const FREE_KASSA_SECRET = process.env.FREE_KASSA_SECRET;
const FREE_KASSA_SECRET_2 = process.env.FREE_KASSA_SECRET_2;

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
  const servers = loadJSON(serversFile, []);
  const donateOptions = loadJSON(donateOptionsFile, {});
  const background = loadJSON(backgroundFile, {});
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
  const servers = loadJSON(serversFile, []);
  const { id, name, ip, avatar, rconHost, rconPort, rconPassword } = req.body;
  servers.push({ id, name, ip, avatar, rconHost, rconPort: parseInt(rconPort), rconPassword });
  saveJSON(serversFile, servers);
  res.redirect('/admin');
});

app.post('/admin/delete-server', requireAdmin, (req, res) => {
  let servers = loadJSON(serversFile, []);
  servers = servers.filter(s => s.id !== req.body.id);
  saveJSON(serversFile, servers);
  res.redirect('/admin');
});

app.post('/admin/add-donate', requireAdmin, (req, res) => {
  const donateOptions = loadJSON(donateOptionsFile, {});
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
  const donateOptions = loadJSON(donateOptionsFile, {});
  const { serverId, id } = req.body;

  if (donateOptions[serverId]) {
    donateOptions[serverId] = donateOptions[serverId].filter(d => d.id !== id);
    saveJSON(donateOptionsFile, donateOptions);
  }

  res.redirect('/admin');
});

// --- Главная страница ---
app.get('/', (req, res) => {
  let background = loadJSON(backgroundFile, {});
  const rulesPath = path.join(__dirname, 'content', 'rules.html');
  const rulesContent = fs.existsSync(rulesPath) 
    ? fs.readFileSync(rulesPath, 'utf8')
    : '<p>Правила ещё не добавлены</p>';
  res.render('index', { content: rulesContent, title: 'Главная - MineOptima', bg: background });
});

// --- Файл покупок ---
const purchasesFile = path.join(__dirname, 'data', 'purchases.json');

// --- API: Статус серверов ---
app.get('/api/server-status', async (req, res) => {
  const servers = loadJSON(serversFile, []);
  const statuses = await Promise.all(servers.map(getServerStatus));
  res.json({ servers: statuses });
});

// --- API: Генерация подписи для ссылки ---
app.get('/api/generate-sign', (req, res) => {
  let { amount, orderId } = req.query;
  if (!amount || !orderId) return res.status(400).json({ error: 'Missing params' });

  amount = parseFloat(amount).toFixed(2);
  const sign = crypto.createHash('md5')
    .update(`${FREE_KASSA_MERCHANT_ID}:${amount}:${FREE_KASSA_SECRET_2}:${orderId}`)
    .digest('hex');

  res.json({ merchantId: FREE_KASSA_MERCHANT_ID, sign });
});

// --- Коллбэк от Free-Kassa ---
app.post('/api/payment-callback', async (req, res) => {
  console.log('Callback received:', req.body);

  if (!req.body || Object.keys(req.body).length === 0) {
    console.error('❌ Пустое тело запроса');
    return res.status(400).send('Empty body');
  }

  try {
    const { MERCHANT_ORDER_ID, AMOUNT, SIGN } = req.body;
    const purchaseId = MERCHANT_ORDER_ID;

    if (!MERCHANT_ORDER_ID || !AMOUNT || !SIGN) {
      console.error('❌ Не хватает данных в теле запроса');
      return res.status(400).send('Missing data');
    }

    const signString = `${FREE_KASSA_MERCHANT_ID}:${parseFloat(AMOUNT).toFixed(2)}:${FREE_KASSA_SECRET}:${MERCHANT_ORDER_ID}`;
    const expectedSign = crypto.createHash('md5').update(signString).digest('hex');

    console.log('Sign string:', signString);
    console.log('Expected:', expectedSign, 'Received:', SIGN);

    if (expectedSign.toLowerCase() !== SIGN.toLowerCase()) {
      console.error('❌ Неверная подпись');
      updatePurchaseStatus(purchaseId, 'canceled');
      return res.status(400).send('Invalid signature');
    }

    const purchases = loadPurchases();
    const purchase = purchases.find(p => String(p.id) === purchaseId);
    if (!purchase) return res.status(404).send('Purchase not found');

    const servers = loadJSON(serversFile, []);
    const srv = servers.find(s => s.id === purchase.server);
    const donateOptions = loadJSON(donateOptionsFile, {});
    const donateInfo = (donateOptions[purchase.server] || []).find(d => String(d.id) === String(purchase.item));

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

    const cmd = donateInfo.rconCommand.replace('{player}', purchase.username);
    await rcon.send(cmd);
    rcon.end();

    updatePurchaseStatus(purchaseId, 'success');
    console.log(`✅ Выдан ${donateInfo.name} игроку ${purchase.username} на ${srv.name}`);

    res.send('YES');
  } catch (err) {
    console.error('❌ Ошибка в обработке callback:', err);
    if (req.body?.MERCHANT_ORDER_ID) updatePurchaseStatus(req.body.MERCHANT_ORDER_ID, 'canceled');
    res.status(500).send('Error');
  }
});


// Функция для обновления статуса
function updatePurchaseStatus(id, status) {
  const purchases = loadPurchases();
  const idx = purchases.findIndex(p => String(p.id) === String(id));
  if (idx !== -1) {
    purchases[idx].status = status;
    purchases[idx].updatedAt = new Date().toISOString();
    saveJSON(purchasesFile, purchases);
  } else {
    console.warn('Покупка не найдена для обновления:', id);
  }
}
app.post('/add-purchase', (req, res) => {
  try {

    const dataDir = path.join(__dirname, 'data');
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

    const purchasesFile = path.join(dataDir, 'purchases.json');
    if (!fs.existsSync(purchasesFile)) fs.writeFileSync(purchasesFile, '[]');

    const purchases = JSON.parse(fs.readFileSync(purchasesFile, 'utf-8'));
    const { username, serverId, donateId, status } = req.body;

    const donateOptions = loadJSON(path.join(__dirname, '/data/donateOptions.json'), {});

    if (!donateOptions[serverId]) {
      console.error('Сервер не найден');
      return res.status(400).json({ error: 'Сервер не найден' });
    }

    const product = donateOptions[serverId].find(d => String(d.id) === String(donateId));

    if (!product) {
      console.error('Товар не найден');
      return res.status(400).json({ error: 'Товар не найден на этом сервере' });
    }

    const newPurchase = {
      id: Date.now(),
      username,
      server: serverId,
      item: product.id,
      amount: product.price,
      status: status || 'progress',
      date: new Date().toISOString()
    };

    purchases.push(newPurchase);
    fs.writeFileSync(purchasesFile, JSON.stringify(purchases, null, 2), 'utf-8');

    res.json({ status: 'ok', id: newPurchase.id, total: purchases.filter(p => p.server === serverId).length });
  } catch (err) {
    console.error('Ошибка /add-purchase:', err);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

app.get('/pay-with-freekassa', (req, res) => {
  const { id } = req.query;
  if (!id) return res.status(400).send('Нет ID покупки');

  const purchases = loadPurchases();
  const purchase = purchases.find(p => String(p.id) === String(id));
  if (!purchase) return res.status(404).send('Покупка не найдена');

  const donateOptions = loadJSON(donateOptionsFile, {});
  const donateInfo = (donateOptions[purchase.server] || []).find(d => String(d.id) === String(purchase.item));
  if (!donateInfo) return res.status(400).send('Ошибка доната');

  const amount = Number(donateInfo.price).toFixed(2);
  const sign = crypto.createHash('md5')
    .update(`${FREE_KASSA_MERCHANT_ID}:${amount}:${FREE_KASSA_SECRET_2}:${purchase.id}`)
    .digest('hex');

  const url = `https://pay.freekassa.ru/?m=${FREE_KASSA_MERCHANT_ID}&oa=${amount}&o=${purchase.id}&s=${sign}&i=0&currency=RUB&lang=ru`;
  res.redirect(url);
});

function loadJSON(filePath, defaultValue = {}) {
  if (fs.existsSync(filePath)) {
    try {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (err) {
      console.error(`Ошибка чтения файла ${filePath}:`, err);
      return defaultValue;
    }
  }
  return defaultValue;
}

function saveJSON(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf-8');
  } catch (err) {
    console.error('Ошибка записи файла:', err);
  }
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

function loadPurchases() {
  if (!fs.existsSync(purchasesFile)) return [];
  const data = fs.readFileSync(purchasesFile, 'utf-8');
  try {
    return JSON.parse(data);
  } catch (err) {
    console.error('Ошибка чтения файла purchases.json:', err);
    return [];
  }
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