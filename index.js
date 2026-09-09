import express from 'express';
import axios from 'axios';
import dotenv from 'dotenv';
import crypto from 'crypto';
import bodyParser from 'body-parser';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import { fileURLToPath } from 'url';
import mongoose from 'mongoose';

dotenv.config();

/*****************************************************************
 * ENVIRONMENT VARIABLES & CONSTANTS
 *****************************************************************/
const {
  SHOPIFY_API_KEY: API_KEY,
  SHOPIFY_API_SECRET: API_SECRET,
  SHOPIFY_SCOPES: SCOPES,
  SHOPIFY_API_VERSION: API_VERSION = '2025-04',
  HOST,
  PORT = 3000,
  APP_UI_PATH = '/app',
} = process.env;
const MONGODB_URI="mongodb+srv://asalimunaafa:2JXVYLlkLFsKu5M5@cluster0.ufhmr.mongodb.net/shopifytest?retryWrites=true&w=majority&appName=Cluster0";
if (!API_KEY || !API_SECRET || !SCOPES || !HOST || !MONGODB_URI) {
  console.error('❌ Missing required environment variables');
  process.exit(1);
}

/*****************************************************************
 * DATABASE SET‑UP (MongoDB via Mongoose)
 *****************************************************************/
await mongoose.connect(MONGODB_URI);
console.log('✅ Connected to MongoDB');

const tokenSchema = new mongoose.Schema({
  shop: { type: String, required: true, unique: true, index: true },
  accessToken: { type: String, required: true },
  scope: String,
  createdAt: { type: Date, default: Date.now },
});

const Token = mongoose.model('Token', tokenSchema);

/*****************************************************************
 * APP INITIALISATION
 *****************************************************************/
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

// In‑memory cache (optional, improves latency but DB is source of truth)
const cache = new Map();
const stateMap = new Map();

/*****************************************************************
 * MIDDLEWARE & VIEW ENGINE
 *****************************************************************/
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Raw body parser for webhook HMAC verification
app.use('/webhooks', bodyParser.raw({ type: '*/*' }));
app.use(bodyParser.json());

/*****************************************************************
 * HELPER FUNCTIONS
 *****************************************************************/
function verifyWebhookHmac(req) {
  const hmac = req.get('X-Shopify-Hmac-Sha256') || '';
  const digest = crypto
    .createHmac('sha256', API_SECRET)
    .update(req.body, 'utf8')
    .digest('base64');
  return crypto.timingSafeEqual(Buffer.from(digest, 'base64'), Buffer.from(hmac, 'base64'));
}

function verifyOAuthCallback(req) {
  const providedHmac = req.query.hmac;
  if (typeof providedHmac !== 'string') return false;
  const { hmac, signature, ...rest } = req.query;
  const sorted = Object.keys(rest)
    .sort()
    .map((k) => `${k}=${rest[k]}`)
    .join('&');
  const generated = crypto.createHmac('sha256', API_SECRET).update(sorted).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(generated, 'hex'), Buffer.from(providedHmac, 'hex'));
}

/**
 * Async helper to fetch or cache tokens.
 * Throws if no token exists for the shop.
 */
async function getToken(shop) {
  if (cache.has(shop)) return cache.get(shop);
  const record = await Token.findOne({ shop });
  if (record) {
    cache.set(shop, record.accessToken);
    return record.accessToken;
  }
  console.warn(`⚠️ No token on record for ${shop}`);
  throw new Error('Missing token for shop – re‑auth required');
}

/*****************************************************************
 * WEBHOOK AUTHENTICATION LAYER
 *****************************************************************/
app.use('/webhooks', (req, res, next) => {
  if (req.method !== 'POST' || !verifyWebhookHmac(req)) {
    console.warn('❌ Invalid webhook HMAC');
    return res.status(401).send('Unauthorized');
  }
  next();
});

/*****************************************************************
 * ROUTES – PUBLIC LANDING / INSTALL FLOW
 *****************************************************************/
app.get('/', (req, res) => {
  const { shop } = req.query;
  if (!shop) {
    return res.redirect('https://www.profitfirstanalytics.co.in/'); // 🟢 Correct: Returns immediately after redirecting
  }
  return res.redirect(`/connect?shop=${encodeURIComponent(shop)}`);
});

app.get('/connect', (req, res) => {
  const { shop } = req.query;
  if (!shop || typeof shop !== 'string') return res.status(400).send('❌ Missing "shop" query parameter');
  const state = uuidv4();
  stateMap.set(state, shop);

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${API_KEY}` +
    `&scope=${encodeURIComponent(SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(`${HOST}/auth/callback`)}` +
    `&state=${state}` +
    `&grant_options[]=offline`;

  res.redirect(installUrl);
});

/*****************************************************************
 * ROUTES – OAUTH CALLBACK
 *****************************************************************/
app.get('/auth/callback', async (req, res) => {
  try {
    const { code, shop, state, host, hmac } = req.query;
    if (!code || !shop || !state || !hmac) return res.status(400).send('❌ Missing OAuth params');
    if (stateMap.get(state) !== shop) return res.status(400).send('❌ State mismatch');
    stateMap.delete(state);
    if (!verifyOAuthCallback(req)) return res.status(400).send('❌ Invalid HMAC');

    // Exchange code for access token
    const tokenRes = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: API_KEY,
      client_secret: API_SECRET,
      code,
    });

    const accessToken = tokenRes.data.access_token;

    // Persist to DB (upsert)
    await Token.findOneAndUpdate(
      { shop },
      { accessToken, scope: SCOPES },
      { upsert: true, new: true }
    );
    cache.set(shop, accessToken);
    console.log(`✅ Token stored for ${shop}`);

    // Register GDPR webhooks (idempotent – Shopify dedupes by callback URL)
    await registerPrivacyWebhooks(shop, accessToken);

    // Redirect back into Admin (embedded) or to stand‑alone UI
    if (host && host.includes('admin.shopify.com')) {
      return res.redirect(`https://${host}/apps/${API_KEY}?shop=${encodeURIComponent(shop)}&host=${encodeURIComponent(host)}`);
    }
    res.redirect(`${HOST}${APP_UI_PATH}?shop=${encodeURIComponent(shop)}`);
  } catch (err) {
    console.error('❌ OAuth callback error:', err.response?.data || err.message);
    res.status(500).send('Authentication failed');
  }
});

app.get('/token', async (req, res) => {
  const { shop, password } = req.query;

  // Check if shop or password is missing
  if (!shop || !password) {
    return res.status(400).json({ error: '❌ Missing "shop" or "password" query parameter' });
  }

  // Check if password is incorrect
  if (password !== "Sachin369") {
    return res.status(403).json({ error: '❌ Invalid password' });
  }

  try {
    const token = await getToken(shop);
    res.json({ accessToken: token });
  } catch (err) {
    console.error(`❌ Error fetching token for ${shop}:`, err.message);
    res.status(404).json({ error: `Token not found for shop: ${shop}` });
  }
});



/*****************************************************************
 * ROUTES – EMBEDDED APP DASHBOARD
 *****************************************************************/
app.get('/app', (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).send('❌ Missing "shop" parameter');
  res.render('app', { shop });
});

/*****************************************************************
 * ROUTES – GRAPHQL PROXIES (Orders / Products / Customers)
 *****************************************************************/
app.get('/orders', async (req, res) => {
  const { shop } = req.query;
  try {
    const token = await getToken(shop);
    const url = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;

    const query = (cursor) => `{
      orders(first: 100${cursor ? `, after: \"${cursor}\"` : ''}) {
        pageInfo { hasNextPage }
        edges { cursor node { id name createdAt totalPriceSet { shopMoney { amount currencyCode } } customer { firstName lastName email } } }
      }
    }`;

    let hasNextPage = true;
    let cursor = null;
    const all = [];
    while (hasNextPage) {
      const { data } = await axios.post(url, { query: query(cursor) }, {
        headers: {
          'X-Shopify-Access-Token': token,
          'Content-Type': 'application/json',
        },
      });

      const { orders } = data.data;
      hasNextPage = orders.pageInfo.hasNextPage;
      if (orders.edges.length) {
        cursor = orders.edges[orders.edges.length - 1].cursor;
        all.push(...orders.edges.map((e) => e.node));
      }
    }

    const totalSales = all.reduce((s, o) => s + parseFloat(o.totalPriceSet.shopMoney.amount), 0);
res.json(all);   // just the array
  } catch (err) {
    console.error('❌ /orders error:', err.response?.data || err.message);
    res.status(500).send('Error fetching orders');
  }
});

app.get('/products', async (req, res) => {
  const { shop } = req.query;
  try {
    const token = await getToken(shop);
    const url = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;

    const query = (cursor) => `{
      products(first: 100${cursor ? `, after: \"${cursor}\"` : ''}) {
        pageInfo { hasNextPage }
        edges { cursor node { id title totalInventory createdAt status } }
      }
    }`;

    let hasNextPage = true;
    let cursor = null;
    const all = [];
    while (hasNextPage) {
      const { data } = await axios.post(url, { query: query(cursor) }, {
        headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' },
      });
      const { products } = data.data;
      hasNextPage = products.pageInfo.hasNextPage;
      if (products.edges.length) {
        cursor = products.edges[products.edges.length - 1].cursor;
        all.push(...products.edges.map((e) => e.node));
      }
    }
    const totalInventory = all.reduce((s, p) => s + (p.totalInventory || 0), 0);
res.json(all);   // just the array
  } catch (err) {
    console.error('❌ /products error:', err.response?.data || err.message);
    res.status(500).send('Error fetching products');
  }
});

app.get('/customers', async (req, res) => {
  const { shop } = req.query;
  try {
    const token = await getToken(shop);
    const url = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;

    const query = (cursor) => `{
      customers(first: 100${cursor ? `, after: \"${cursor}\"` : ''}) {
        pageInfo { hasNextPage }
        edges { cursor node { id displayName email createdAt state } }
      }
    }`;

    let hasNextPage = true;
    let cursor = null;
    const all = [];
    while (hasNextPage) {
      const { data } = await axios.post(url, { query: query(cursor) }, {
        headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' },
      });
      const { customers } = data.data;
      hasNextPage = customers.pageInfo.hasNextPage;
      if (customers.edges.length) {
        cursor = customers.edges[customers.edges.length - 1].cursor;
        all.push(...customers.edges.map((e) => e.node));
      }
    }
res.json(all);   // just the array
  } catch (err) {
    console.error('❌ /customers error:', err.response?.data || err.message);
    res.status(500).send('Error fetching customers');
  }
});

/*****************************************************************
 * ROUTES – GDPR / PRIVACY WEBHOOKS
 *****************************************************************/
app.get('/privacy', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

app.post('/webhooks/orders/create', (req, res) => {
  console.log('📦 Order Created:', JSON.parse(req.body.toString('utf8')));
  res.status(200).send('OK');
});
app.post('/webhooks/customers/data_request', (req, res) => {
  console.log('🔐 customers/data_request:', JSON.parse(req.body.toString()));
  res.status(200).send('OK');
});
app.post('/webhooks/customers/redact', (req, res) => {
  console.log('🧹 customers/redact:', JSON.parse(req.body.toString()));
  res.status(200).send('OK');
});
app.post('/webhooks/shop/redact', (req, res) => {
  console.log('🏪 shop/redact:', JSON.parse(req.body.toString()));
  res.status(200).send('OK');
});

async function registerPrivacyWebhooks(shop, accessToken) {
  const url = `https://${shop}/admin/api/${API_VERSION}/graphql.json`;
  const topics = [
    { topic: 'CUSTOMERS_DATA_REQUEST', path: '/webhooks/customers/data_request' },
    { topic: 'CUSTOMERS_REDACT', path: '/webhooks/customers/redact' },
    { topic: 'SHOP_REDACT', path: '/webhooks/shop/redact' },
  ];

  for (const { topic, path } of topics) {
    const mutation = `mutation { webhookSubscriptionCreate(topic: ${topic}, webhookSubscription: { callbackUrl: \"${HOST}${path}\", format: JSON }) { webhookSubscription { id } userErrors { field message } } }`;
    try {
      const response = await axios.post(
        url,
        { query: mutation },
        { headers: { 'X-Shopify-Access-Token': accessToken, 'Content-Type': 'application/json' } }
      );
      const errors = response.data?.data?.webhookSubscriptionCreate?.userErrors;
      if (errors?.length) console.error(`❌ ${topic} errors:`, errors);
      else console.log(`✅ Registered webhook: ${topic}`);
    } catch (err) {
      console.error(`❌ Webhook registration failed for ${topic}:`, err.response?.data || err.message);
    }
  }
}

/*****************************************************************
 * SERVER STARTUP
 *****************************************************************/
app.listen(PORT, () => console.log(`🚀 Shopify app running on ${HOST}:${PORT}`));
