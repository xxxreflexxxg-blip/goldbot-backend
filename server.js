// ================================================================
// GOLDBOT PRO — Backend Server
// Node.js + Express + Supabase
// ================================================================
require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 4000;

// ── SUPABASE CLIENT ──────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── MIDDLEWARE ───────────────────────────────────────────────────
app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,PATCH,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") { res.sendStatus(200); } 
  else { next(); }
});

// ── AUTH MIDDLEWARE ──────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── HELPER: Generate unique ref code ────────────────────────────
function generateRefCode(name) {
  const clean = name.replace(/\s+/g, '').toUpperCase().slice(0, 5);
  const rand  = Math.floor(Math.random() * 9000) + 1000;
  return clean + rand;
}

// ================================================================
// AUTH ROUTES
// ================================================================

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, refCode } = req.body;

    if (!name || !email || !password)
      return res.status(400).json({ error: 'Name, email and password are required' });

    // Check email exists
    const { data: existing } = await supabase
      .from('users').select('id').eq('email', email).single();
    if (existing) return res.status(400).json({ error: 'Email already registered' });

    // Find referrer (parent)
    let parentId = null;
    if (refCode) {
      const { data: referrer } = await supabase
        .from('users').select('id').eq('ref_code', refCode).single();
      if (referrer) parentId = referrer.id;
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);

    // Generate unique ref code
    let newRefCode = generateRefCode(name);
    // Ensure uniqueness
    let attempt = 0;
    while (attempt < 5) {
      const { data: codeCheck } = await supabase
        .from('users').select('id').eq('ref_code', newRefCode).single();
      if (!codeCheck) break;
      newRefCode = generateRefCode(name);
      attempt++;
    }

    // Create user
    const { data: user, error } = await supabase
      .from('users')
      .insert({ name, email, password_hash: passwordHash, ref_code: newRefCode, parent_id: parentId })
      .select()
      .single();

    if (error) return res.status(500).json({ error: error.message });

    // If referred — credit $100 bonus to referrer
    if (parentId) {
      await supabase.from('commissions').insert({
        from_user_id: user.id,
        to_user_id:   parentId,
        level:        1,
        amount:       100,
        type:         'bonus',
        status:       'paid'
      });
      await supabase.rpc('increment_wallet', { uid: parentId, amount: 100 });
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, refCode: user.ref_code, wallet: user.wallet, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    // Admin login
    if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASS) {
      const token = jwt.sign({ id: 'admin', email, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '7d' });
      return res.json({ token, user: { id: 'admin', name: 'Admin', email, role: 'admin' } });
    }

    const { data: user } = await supabase
      .from('users').select('*').eq('email', email).single();
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, refCode: user.ref_code, wallet: user.wallet, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================================================================
// USER ROUTES (protected)
// ================================================================

// GET /api/user/me — get current user + stats
app.get('/api/user/me', authMiddleware, async (req, res) => {
  try {
    const { data: user } = await supabase
      .from('users').select('*').eq('id', req.user.id).single();
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Stats
    const { data: l1comm } = await supabase.from('commissions')
      .select('amount').eq('to_user_id', user.id).eq('level', 1).eq('status', 'paid');
    const { data: l2comm } = await supabase.from('commissions')
      .select('amount').eq('to_user_id', user.id).eq('level', 2).eq('status', 'paid');
    const { data: l1refs } = await supabase.from('users')
      .select('id,name,email,status,created_at').eq('parent_id', user.id);

    const l1Total = l1comm?.reduce((s, c) => s + Number(c.amount), 0) || 0;
    const l2Total = l2comm?.reduce((s, c) => s + Number(c.amount), 0) || 0;

    res.json({
      user: { id: user.id, name: user.name, email: user.email, refCode: user.ref_code, wallet: Number(user.wallet), role: user.role, status: user.status },
      stats: { l1Total, l2Total, l1Refs: l1refs?.length || 0 },
      l1Referrals: l1refs || [],
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/user/network — full L1 + L2 network
app.get('/api/user/network', authMiddleware, async (req, res) => {
  try {
    const { data: l1 } = await supabase.from('users')
      .select('id,name,email,status,created_at,wallet').eq('parent_id', req.user.id);

    const l1Ids = l1?.map(u => u.id) || [];
    let l2 = [];
    if (l1Ids.length > 0) {
      const { data } = await supabase.from('users')
        .select('id,name,email,status,created_at,parent_id').in('parent_id', l1Ids);
      l2 = data || [];
    }

    res.json({ l1: l1 || [], l2 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/user/commissions — commission history
app.get('/api/user/commissions', authMiddleware, async (req, res) => {
  try {
    const { data } = await supabase.from('commissions')
      .select('*, from_user:from_user_id(name)')
      .eq('to_user_id', req.user.id)
      .order('created_at', { ascending: false });
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/user/withdrawals — withdrawal history
app.get('/api/user/withdrawals', authMiddleware, async (req, res) => {
  try {
    const { data } = await supabase.from('withdrawals')
      .select('*').eq('user_id', req.user.id).order('requested_at', { ascending: false });
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/user/withdraw — request withdrawal
app.post('/api/user/withdraw', authMiddleware, async (req, res) => {
  try {
    const { amount, method, address } = req.body;
    if (!amount || amount < 50) return res.status(400).json({ error: 'Minimum withdrawal is $50' });
    if (!method || !address)   return res.status(400).json({ error: 'Method and address required' });

    const { data: user } = await supabase.from('users').select('wallet').eq('id', req.user.id).single();
    if (!user || Number(user.wallet) < amount) return res.status(400).json({ error: 'Insufficient balance' });

    // Deduct from wallet
    await supabase.from('users').update({ wallet: Number(user.wallet) - Number(amount) }).eq('id', req.user.id);

    // Create withdrawal request
    const { data: withdrawal, error } = await supabase.from('withdrawals')
      .insert({ user_id: req.user.id, amount, method, address }).select().single();

    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true, withdrawal });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================================================================
// ADMIN ROUTES
// ================================================================

// GET /api/admin/users
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { data } = await supabase.from('users')
      .select('id,name,email,ref_code,parent_id,wallet,role,status,created_at')
      .order('created_at', { ascending: false });
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/commissions
app.get('/api/admin/commissions', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { data } = await supabase.from('commissions')
      .select('*, from_user:from_user_id(name), to_user:to_user_id(name)')
      .order('created_at', { ascending: false });
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/withdrawals
app.get('/api/admin/withdrawals', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { data } = await supabase.from('withdrawals')
      .select('*, user:user_id(name,email)')
      .order('requested_at', { ascending: false });
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/admin/withdrawals/:id — approve or reject
app.patch('/api/admin/withdrawals/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { status, note } = req.body;
    if (!['approved', 'rejected'].includes(status))
      return res.status(400).json({ error: 'Status must be approved or rejected' });

    const { data: w } = await supabase.from('withdrawals').select('*').eq('id', req.params.id).single();
    if (!w) return res.status(404).json({ error: 'Withdrawal not found' });

    // If rejected — refund wallet
    if (status === 'rejected') {
      const { data: user } = await supabase.from('users').select('wallet').eq('id', w.user_id).single();
      await supabase.from('users').update({ wallet: Number(user.wallet) + Number(w.amount) }).eq('id', w.user_id);
    }

    await supabase.from('withdrawals').update({ status, note, processed_at: new Date() }).eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/admin/users/:id/wallet — manually adjust wallet
app.patch('/api/admin/users/:id/wallet', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { amount, note } = req.body;
    const { data: user } = await supabase.from('users').select('wallet').eq('id', req.params.id).single();
    if (!user) return res.status(404).json({ error: 'User not found' });

    const newWallet = Number(user.wallet) + Number(amount);
    await supabase.from('users').update({ wallet: newWallet }).eq('id', req.params.id);
    res.json({ success: true, newWallet });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/stats
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { count: totalUsers }    = await supabase.from('users').select('*', { count: 'exact', head: true });
    const { count: totalWithdr }   = await supabase.from('withdrawals').select('*', { count: 'exact', head: true });
    const { data: pendingW }       = await supabase.from('withdrawals').select('amount').eq('status', 'pending');
    const { data: totalCommD }     = await supabase.from('commissions').select('amount').eq('status', 'paid');

    res.json({
      totalUsers,
      totalWithdrawals:   totalWithdr,
      pendingPayouts:     pendingW?.reduce((s, w) => s + Number(w.amount), 0) || 0,
      totalCommissions:   totalCommD?.reduce((s, c) => s + Number(c.amount), 0) || 0,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================================================================
// BILLING WEBHOOK (called by Stripe or manually)
// POST /api/billing/process
// ================================================================
app.post('/api/billing/process', async (req, res) => {
  try {
    const { subscriptionId } = req.body;
    await supabase.rpc('credit_commissions', { subscription_id: subscriptionId });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── START ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`GoldBot API running on http://localhost:${PORT}`);
});
