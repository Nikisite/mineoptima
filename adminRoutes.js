const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();
const bcrypt = require('bcrypt');
require('dotenv').config();

const ADMIN_LOGIN_HASH = process.env.ADMIN_LOGIN; 
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;

// Проверка username
async function checkAdminUsername(inputUsername) {
  if (!ADMIN_LOGIN_HASH) throw new Error('Admin username hash not set');
  return bcrypt.compare(inputUsername, ADMIN_LOGIN_HASH);
}

// Проверка пароля
async function checkAdminPassword(inputPassword) {
  if (!ADMIN_PASSWORD_HASH) throw new Error('Admin password hash not set');
  return bcrypt.compare(inputPassword, ADMIN_PASSWORD_HASH);
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

function loadServers() {
  try {
    return JSON.parse(fs.readFileSync(serversPath, 'utf8'));
  } catch (err) {
    console.error('Ошибка чтения servers.json:', err);
    return [];
  }
}

function saveServers(data) {
  try {
    fs.writeFileSync(serversPath, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error('Ошибка записи servers.json:', err);
  }
}

function loadDonates() {
  try {
    return JSON.parse(fs.readFileSync(donatePath, 'utf8'));
  } catch (err) {
    console.error('Ошибка чтения donateOptions.json:', err);
    return {};
  }
}

function saveDonates(data) {
  try {
    fs.writeFileSync(donatePath, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error('Ошибка записи donateOptions.json:', err);
  }
}

// Админ-панель
router.get('/admin', requireAdmin, (req, res) => {
  const servers = loadServers();
  const donateOptions = loadDonates();
  let background = { image: '' };

  try {
    background = JSON.parse(fs.readFileSync(backgroundPath, 'utf8'));
  } catch {
    background = { image: '' };
  }

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
  servers.push(req.body);
  saveServers(servers);
  res.redirect('/admin');
});

router.post('/admin/delete-server', requireAdmin, (req, res) => {
  const serversPath = path.join(__dirname, '/data/servers.json');
  const donatePath = path.join(__dirname, '/data/donateOptions.json');

  let servers = [];
  try {
    servers = JSON.parse(fs.readFileSync(serversPath, 'utf8'));
  } catch (err) {
    console.error('Ошибка чтения servers.json:', err);
  }

  let donateOptions = {};
  try {
    donateOptions = JSON.parse(fs.readFileSync(donatePath, 'utf8'));
  } catch (err) {
    console.error('Ошибка чтения donateOptions.json:', err);
  }

  const serverIdToDelete = req.body.id;
  console.log('Удаляем сервер с id:', serverIdToDelete);

  servers = servers.filter(srv => srv.id !== serverIdToDelete);

  if (donateOptions.hasOwnProperty(serverIdToDelete)) {
    delete donateOptions[serverIdToDelete];
    console.log(`Донаты сервера ${serverIdToDelete} удалены.`);
  } else {
    console.log(`Донатов для сервера ${serverIdToDelete} не найдено.`);
  }

  try {
    fs.writeFileSync(serversPath, JSON.stringify(servers, null, 2), 'utf8');
    fs.writeFileSync(donatePath, JSON.stringify(donateOptions, null, 2), 'utf8');
  } catch (err) {
    console.error('Ошибка записи данных при удалении сервера:', err);
    return res.status(500).send('Ошибка сервера при удалении');
  }

  res.redirect('/admin');
});


// Добавление доната
router.post('/add-donate', requireAdmin, (req, res) => {
  const donateOptions = loadDonates();
  const server = req.body.server;
  if (!donateOptions[server]) {
    donateOptions[server] = [];
  }

  donateOptions[server].push({
    id: req.body.id,
    name: req.body.name,
    price: parseInt(req.body.price, 10),
    desc: req.body.desc,
    rconCommand: req.body.rconCommand
  });

  saveDonates(donateOptions);
  res.redirect('/admin');
});

// Удаление доната
router.post('/delete-donate', requireAdmin, (req, res) => {
  const donateOptions = loadDonates();
  const server = req.body.server;
  if (donateOptions[server]) {
    donateOptions[server] = donateOptions[server].filter(d => d.id !== req.body.id);
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

// Сохранение правил
router.post('/save-rules', requireAdmin, (req, res) => {
  const rulesPath = path.join(__dirname, '/content/rules.html');
  const newRules = req.body.rules || '';
  try {
    fs.writeFileSync(rulesPath, newRules, 'utf8');
    res.redirect('/admin');
  } catch (err) {
    console.error('Ошибка сохранения правил:', err);
    res.status(500).send('Не удалось сохранить правила');
  }
});

// Редактирование сервера
router.post('/edit-server', requireAdmin, (req, res) => {
  const servers = loadServers();
  const serverIndex = servers.findIndex(srv => srv.id === req.body.id);
  if (serverIndex !== -1) {
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
  }
  res.redirect('/admin');
});

// Редактирование доната
router.post('/edit-donate', requireAdmin, (req, res) => {
  const donates = loadDonates();
  const server = req.body.server;
  if (donates[server]) {
    const donateIndex = donates[server].findIndex(d => d.id === req.body.id);
    if (donateIndex !== -1) {
      donates[server][donateIndex] = {
        ...donates[server][donateIndex],
        name: req.body.name,
        price: parseFloat(req.body.price),
        desc: req.body.desc,
        rconCommand: req.body.rconCommand,
      };
      saveDonates(donates);
    }
  }
  res.redirect('/admin');
});

const purchasesPath = path.join(__dirname, '/data/purchases.json');

function loadPurchases() {
  try {
    return JSON.parse(fs.readFileSync(purchasesPath, 'utf8'));
  } catch (err) {
    console.error('Ошибка чтения purchases.json:', err);
    return [];
  }
}

function savePurchases(data) {
  try {
    fs.writeFileSync(purchasesPath, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error('Ошибка записи purchases.json:', err);
  }
}

// Обработчик добавления покупки
router.post('/add-purchase', requireAdmin, (req, res) => {
  const { username, item, server, amount, status } = req.body;
  const purchases = loadPurchases();

  purchases.push({
    id: Date.now(),
    username,
    item,
    server,
    amount,
    status,
    date: new Date().toISOString()
  });

  savePurchases(purchases);
  res.json({ success: true });
});

// Обновление статуса
router.post('/update-purchase-status', (req, res) => {
  const { id, status } = req.body;

  if (!id || !status) {
    return res.status(400).json({ error: 'ID и новый статус обязательны' });
  }

  const purchases = loadPurchases();
  const purchaseIndex = purchases.findIndex(p => String(p.id) === String(id));

  if (purchaseIndex === -1) {
    return res.status(404).json({ error: 'Покупка не найдена' });
  }

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
router.get('/admin/purchases', requireAdmin, (req, res) => {
  const purchases = loadPurchases();
  res.render('admin/purchases', { purchases });
});


module.exports = router;