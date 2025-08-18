const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();
const bcrypt = require('bcrypt');
require('dotenv').config();

async function checkAdminUsername(inputUsername) {
  return inputUsername === process.env.ADMIN_LOGIN;
}

async function checkAdminPassword(inputPassword) {
  if (!process.env.ADMIN_PASSWORD_HASH) throw new Error('Admin password hash not set');
  return bcrypt.compare(inputPassword, process.env.ADMIN_PASSWORD_HASH);
}

router.post('/login', async (req, res) => {
  try {
    const userOk = await checkAdminUsername(req.body.username);
    const passOk = await checkAdminPassword(req.body.password);

    if (userOk && passOk) {
      req.session.isAdmin = true;
      res.redirect('/admin');
    } else {
      res.status(401).send('Неверный логин или пароль');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Ошибка сервера');
  }
});

// Middleware для проверки авторизации
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    next();
  } else {
    res.redirect('/admin/login');
  }
}

// Логаут
router.get('/admin/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(() => {
      res.redirect('/');
    });
  } else {
    res.redirect('/');
  }
});

const serversPath = path.join(__dirname, '/data/servers.json');
const donatePath = path.join(__dirname, '/data/donateOptions.json');
const backgroundPath = path.join(__dirname, '/data/background.json');
const purchasesPath = path.join(__dirname, '/data/purchases.json');

// ---- Утилиты ----
function loadServers() {
  try {
    return JSON.parse(fs.readFileSync(serversPath, 'utf8'));
  } catch {
    return [];
  }
}
function saveServers(data) {
  fs.writeFileSync(serversPath, JSON.stringify(data, null, 2), 'utf8');
}
function loadDonates() {
  try {
    return JSON.parse(fs.readFileSync(donatePath, 'utf8'));
  } catch {
    return {};
  }
}
function saveDonates(data) {
  fs.writeFileSync(donatePath, JSON.stringify(data, null, 2), 'utf8');
}
function loadPurchases() {
  try {
    return JSON.parse(fs.readFileSync(purchasesPath, 'utf8'));
  } catch {
    return [];
  }
}
function savePurchases(data) {
  fs.writeFileSync(purchasesPath, JSON.stringify(data, null, 2), 'utf8');
}

// ---- Роуты админки ----

// Админ-панель
router.get('/admin', requireAdmin, (req, res) => {
  const servers = loadServers();
  const donateOptions = loadDonates();
  let background = { image: '' };

  try {
    background = JSON.parse(fs.readFileSync(backgroundPath, 'utf8'));
  } catch {}

  res.render('admin/dashboard', { servers, donateOptions, background });
});

// Сохранение фона
router.post('/admin/set-background', requireAdmin, (req, res) => {
  const image = req.body.image || '';
  fs.writeFileSync(backgroundPath, JSON.stringify({ image }, null, 2), 'utf8');
  res.redirect('/admin');
});

// Добавление сервера
router.post('/admin/add-server', requireAdmin, (req, res) => {
  const servers = loadServers();
  const newId = servers.length ? Math.max(...servers.map(s => s.id)) + 1 : 1;

  const newServer = {
    id: newId,
    name: req.body.name,
    ip: req.body.ip,
    avatar: req.body.avatar || '',
    rconHost: req.body.rconHost || '',
    rconPort: req.body.rconPort || '',
    rconPassword: req.body.rconPassword || ''
  };

  servers.push(newServer);
  saveServers(servers);
  res.redirect('/admin');
});

// Удаление сервера
router.post('/delete-server', requireAdmin, (req, res) => {
  let servers = loadServers();
  let donateOptions = loadDonates();
  const serverIdToDelete = String(req.body.id);

  const newServers = servers.filter(srv => String(srv.id) !== serverIdToDelete);

  if (Object.prototype.hasOwnProperty.call(donateOptions, serverIdToDelete)) {
    delete donateOptions[serverIdToDelete];
  }

  saveServers(newServers);
  saveDonates(donateOptions);

  res.redirect('/admin');
});


router.post('/add-donate', requireAdmin, (req, res) => {
  const { serverId, name, price, desc, rconCommand } = req.body;

  let donateOptions = loadDonates();

  const serverDonates = donateOptions[serverId] || [];

  const nextId = serverDonates.length > 0
    ? Math.max(...serverDonates.map(d => Number(d.id))) + 1
    : 1;

  const newDonate = {
    id: nextId.toString(),
    name,
    price: Number(price),
    desc,
    rconCommand
  };

  if (!donateOptions[serverId]) donateOptions[serverId] = [];
  donateOptions[serverId].push(newDonate);

  saveDonates(donateOptions);

  res.redirect('/admin');
});

// Удаление доната
router.post('/delete-donate', requireAdmin, (req, res) => {
  const donateOptions = loadDonates();
  const serverId = String(req.body.serverId);

  if (donateOptions[serverId]) {
    donateOptions[serverId] = donateOptions[serverId].filter(d => d.id !== req.body.id);
    saveDonates(donateOptions);
  }
  res.redirect('/admin');
});

// Редактирование правил
router.get('/edit-rules', requireAdmin, (req, res) => {
  const rulesPath = path.join(__dirname, '/content/rules.html');
  let rulesHtml = '';
  try {
    rulesHtml = fs.readFileSync(rulesPath, 'utf8');
  } catch {
    rulesHtml = '<p>Правила пока не заданы.</p>';
  }
  res.render('admin/edit-rules', { rules: rulesHtml });
});

router.post('/save-rules', requireAdmin, (req, res) => {
  const rulesPath = path.join(__dirname, '/content/rules.html');
  fs.writeFileSync(rulesPath, req.body.rules || '', 'utf8');
  res.redirect('/admin');
});

// Редактирование сервера
router.post('/edit-server', requireAdmin, (req, res) => {
  const servers = loadServers();
  const serverIndex = servers.findIndex(srv => String(srv.id) === String(req.body.id));
  if (serverIndex === -1) return res.status(404).send('Сервер не найден');

  servers[serverIndex] = {
    ...servers[serverIndex],
    name: req.body.name,
    ip: req.body.ip,
    avatar: req.body.avatar,
    rconHost: req.body.rconHost,
    rconPort: req.body.rconPort,
    rconPassword: req.body.rconPassword,
  };

  saveServers(servers);
  res.redirect('/admin');
});

// Редактирование доната (форма)
router.get('/edit-donate/:id', requireAdmin, (req, res) => {
  const donateOptions = loadDonates();
  const donateId = String(req.params.id);
  const serverId = String(req.query.serverId);

  if (!donateOptions[serverId]) return res.status(404).send('Server not found');
  const donate = donateOptions[serverId].find(d => String(d.id) === donateId);
  if (!donate) return res.status(404).send('Donate not found');

  res.render('admin/edit-donate', { donate, serverId });
});

// Редактирование доната (сохранение)
router.post('/edit-donate/:id', requireAdmin, (req, res) => {
  const donateOptions = loadDonates();
  const donateId = String(req.params.id);
  const serverId = String(req.body.serverId);

  if (!donateOptions[serverId]) return res.status(404).send('Server not found');

  const donateIndex = donateOptions[serverId].findIndex(d => String(d.id) === donateId);
  if (donateIndex === -1) return res.status(404).send('Donate not found');

  donateOptions[serverId][donateIndex] = {
    ...donateOptions[serverId][donateIndex],
    name: req.body.name,
    price: parseInt(req.body.price, 10),
    desc: req.body.desc || '',
    rconCommand: req.body.rconCommand
  };

  saveDonates(donateOptions);
  res.redirect('/admin');
});

router.post('/add-purchase', (req, res) => {
  const { username, serverId, donateId, serverTitle, status } = req.body;
  console.log("📩 req.body:", req.body);

  if (!username || !serverId || !donateId) {
    return res.status(400).json({ error: 'Не все обязательные поля переданы' });
  }

  const donateOptions = loadDonates();
  console.log("📦 donateOptions keys:", Object.keys(donateOptions));

  const servers = loadServers();
  console.log("📦 servers:", servers);

  const product = donateOptions[serverId]?.find(d => String(d.id) === String(donateId));
  const server = servers.find(s => String(s.id) === String(serverId));

  const newPurchase = {
    id: Date.now().toString(),
    username,
    serverId,
    serverTitle: server ? server.name : '??',
    donateId,
    itemName: product ? product.name : '??',
    amount: product ? product.price : 0,
    status: status || 'progress',
    date: new Date().toISOString()
  };

  console.log("📦 Новый purchase:", newPurchase);

  const purchases = loadPurchases();
  purchases.push(newPurchase);
  savePurchases(purchases);

  res.json({ success: true, id: newPurchase.id });
});

router.post('/update-purchase-status', (req, res) => {
  const { id, status } = req.body;

  if (!id || !status) return res.status(400).json({ error: 'ID и новый статус обязательны' });

  const purchases = loadPurchases();
  const purchaseIndex = purchases.findIndex(p => String(p.id) === String(id));
  if (purchaseIndex === -1) return res.status(404).json({ error: 'Покупка не найдена' });

  purchases[purchaseIndex].status = status;
  purchases[purchaseIndex].updatedAt = new Date().toISOString();

  savePurchases(purchases);
  res.json({ success: true, updated: purchases[purchaseIndex] });
});

// Удаление покупки
router.post('/delete-purchase', requireAdmin, (req, res) => {
  const { id } = req.body;

  if (!id) {
    return res.status(400).json({ error: 'Не указан ID покупки' });
  }

  let purchases = loadPurchases();
  const index = purchases.findIndex(p => String(p.id) === String(id));

  if (index === -1) {
    return res.status(404).json({ error: 'Покупка не найдена' });
  }

  purchases.splice(index, 1);
  savePurchases(purchases);

  res.redirect('/admin/purchases');
});


// Страница покупок
router.get('/purchases', requireAdmin, (req, res) => {
  const purchases = loadPurchases();
  res.render('admin/purchases', { purchases });
});

module.exports = router;
