require('dotenv').config();
const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app  = express();
const PORT = process.env.PORT || 3000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// CORS - lejo te gjitha
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use(express.json());

// Auth middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
}
function admin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

function genCode(name) {
  const c = name.replace(/\s+/g,'').toUpperCase().slice(0,5);
  return c + (Math.floor(Math.random()*9000)+1000);
}

// ── ROUTES ──────────────────────────────────────────────────────
app.get('/', (req,res) => res.json({ status:'GoldBot API running' }));

// REGISTER
app.post('/api/auth/register', async (req,res) => {
  try {
    const { name, email, password, refCode } = req.body;
    if (!name||!email||!password) return res.status(400).json({ error:'All fields required' });

    const { data: ex } = await supabase.from('users').select('id').eq('email',email).single();
    if (ex) return res.status(400).json({ error:'Email already registered' });

    let parentId = null;
    if (refCode) {
      const { data: ref } = await supabase.from('users').select('id').eq('ref_code',refCode).single();
      if (ref) parentId = ref.id;
    }

    const hash = await bcrypt.hash(password, 12);
    let code = genCode(name);

    const { data: user, error } = await supabase.from('users')
      .insert({ name, email, password_hash:hash, ref_code:code, parent_id:parentId })
      .select().single();
    if (error) return res.status(500).json({ error: error.message });

    // NUK kreditohet komisioni ketu - vetem kur bli EA dhe admini konfirmon

    const token = jwt.sign({ id:user.id, email:user.email, role:user.role }, process.env.JWT_SECRET, { expiresIn:'7d' });
    res.json({ token, user:{ id:user.id, name:user.name, email:user.email, refCode:user.ref_code, wallet:user.wallet, role:user.role }});
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// LOGIN
app.post('/api/auth/login', async (req,res) => {
  try {
    const { email, password } = req.body;
    if (email===process.env.ADMIN_EMAIL && password===process.env.ADMIN_PASS) {
      const token = jwt.sign({ id:'admin', email, role:'admin' }, process.env.JWT_SECRET, { expiresIn:'7d' });
      return res.json({ token, user:{ id:'admin', name:'Admin', email, role:'admin' }});
    }
    const { data: user } = await supabase.from('users').select('*').eq('email',email).single();
    if (!user) return res.status(401).json({ error:'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error:'Invalid credentials' });
    const token = jwt.sign({ id:user.id, email:user.email, role:user.role }, process.env.JWT_SECRET, { expiresIn:'7d' });
    res.json({ token, user:{ id:user.id, name:user.name, email:user.email, refCode:user.ref_code, wallet:user.wallet, role:user.role }});
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ME
app.get('/api/user/me', auth, async (req,res) => {
  try {
    const { data: user } = await supabase.from('users').select('*').eq('id',req.user.id).single();
    if (!user) return res.status(404).json({ error:'Not found' });
    const { data: l1 } = await supabase.from('commissions').select('amount').eq('to_user_id',user.id).eq('level',1).eq('status','paid');
    const { data: l2 } = await supabase.from('commissions').select('amount').eq('to_user_id',user.id).eq('level',2).eq('status','paid');
    const { data: refs } = await supabase.from('users').select('id,name,email,status,created_at').eq('parent_id',user.id);
    res.json({
      user:{ id:user.id, name:user.name, email:user.email, refCode:user.ref_code, wallet:Number(user.wallet), role:user.role, status:user.status },
      stats:{ l1Total:l1?.reduce((s,c)=>s+Number(c.amount),0)||0, l2Total:l2?.reduce((s,c)=>s+Number(c.amount),0)||0, l1Refs:refs?.length||0 },
      l1Referrals: refs||[]
    });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// NETWORK
app.get('/api/user/network', auth, async (req,res) => {
  try {
    const { data: l1 } = await supabase.from('users').select('id,name,email,status,created_at').eq('parent_id',req.user.id);
    const ids = l1?.map(u=>u.id)||[];
    let l2 = [];
    if (ids.length) { const { data } = await supabase.from('users').select('id,name,email,status,created_at,parent_id').in('parent_id',ids); l2=data||[]; }
    res.json({ l1:l1||[], l2 });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// COMMISSIONS
app.get('/api/user/commissions', auth, async (req,res) => {
  try {
    const { data } = await supabase.from('commissions')
      .select('*, from_user:from_user_id(name)').eq('to_user_id',req.user.id).order('created_at',{ascending:false});
    res.json(data||[]);
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// WITHDRAWALS USER
app.get('/api/user/withdrawals', auth, async (req,res) => {
  try {
    const { data } = await supabase.from('withdrawals').select('*').eq('user_id',req.user.id).order('requested_at',{ascending:false});
    res.json(data||[]);
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// WITHDRAW REQUEST
app.post('/api/user/withdraw', auth, async (req,res) => {
  try {
    const { amount, method, address } = req.body;
    if (!amount||amount<50) return res.status(400).json({ error:'Minimum $50' });
    const { data: user } = await supabase.from('users').select('wallet').eq('id',req.user.id).single();
    if (Number(user.wallet)<amount) return res.status(400).json({ error:'Insufficient balance' });
    await supabase.from('users').update({ wallet:Number(user.wallet)-Number(amount) }).eq('id',req.user.id);
    const { data: w } = await supabase.from('withdrawals').insert({ user_id:req.user.id, amount, method, address }).select().single();
    res.json({ success:true, withdrawal:w });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ADMIN
app.get('/api/admin/users', auth, admin, async (req,res) => {
  try { const { data } = await supabase.from('users').select('*').order('created_at',{ascending:false}); res.json(data||[]); }
  catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/admin/commissions', auth, admin, async (req,res) => {
  try {
    const { data } = await supabase.from('commissions')
      .select('*, from_user:from_user_id(name), to_user:to_user_id(name)').order('created_at',{ascending:false});
    res.json(data||[]);
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/admin/withdrawals', auth, admin, async (req,res) => {
  try {
    const { data } = await supabase.from('withdrawals').select('*, user:user_id(name,email)').order('requested_at',{ascending:false});
    res.json(data||[]);
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.patch('/api/admin/withdrawals/:id', auth, admin, async (req,res) => {
  try {
    const { status, note } = req.body;
    const { data: w } = await supabase.from('withdrawals').select('*').eq('id',req.params.id).single();
    if (status==='rejected') {
      const { data: u } = await supabase.from('users').select('wallet').eq('id',w.user_id).single();
      await supabase.from('users').update({ wallet:Number(u.wallet)+Number(w.amount) }).eq('id',w.user_id);
    }
    await supabase.from('withdrawals').update({ status, note, processed_at:new Date() }).eq('id',req.params.id);
    res.json({ success:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.patch('/api/admin/users/:id/wallet', auth, admin, async (req,res) => {
  try {
    const { amount } = req.body;
    const { data: u } = await supabase.from('users').select('wallet').eq('id',req.params.id).single();
    const nw = Number(u.wallet)+Number(amount);
    await supabase.from('users').update({ wallet:nw }).eq('id',req.params.id);
    res.json({ success:true, newWallet:nw });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/admin/stats', auth, admin, async (req,res) => {
  try {
    const { count: tu } = await supabase.from('users').select('*',{count:'exact',head:true});
    const { count: tw } = await supabase.from('withdrawals').select('*',{count:'exact',head:true});
    const { data: pw } = await supabase.from('withdrawals').select('amount').eq('status','pending');
    const { data: tc } = await supabase.from('commissions').select('amount').eq('status','paid');
    res.json({ totalUsers:tu, totalWithdrawals:tw,
      pendingPayouts:pw?.reduce((s,w)=>s+Number(w.amount),0)||0,
      totalCommissions:tc?.reduce((s,c)=>s+Number(c.amount),0)||0 });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// PURCHASE - ruaj blerjen, MOS krijo komisione ende
app.post('/api/user/purchase', auth, async (req,res) => {
  try {
    const { method, amount, txhash } = req.body;

    // Kontrollo nese ka blerë tashmë
    const { data: existing } = await supabase.from('sales')
      .select('id').eq('buyer_id',req.user.id).eq('status','delivered').single();
    if(existing) return res.status(400).json({ error:'You already purchased this EA' });

    // Krijo purchase record - komisioni do behet vetem pas konfirmimit
    const { data: purchase, error } = await supabase.from('sales')
      .insert({ buyer_id:req.user.id, plan:'lifetime', amount:amount||400,
        payment_method: method, tx_hash: txhash||null,
        bonus_paid:false, status:'pending' })
      .select().single();
    if(error) return res.status(500).json({ error:error.message });

    res.json({ success:true, purchase });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ADMIN PURCHASES
app.get('/api/admin/purchases', auth, admin, async (req,res) => {
  try {
    const { data } = await supabase.from('sales')
      .select('*, buyer:buyer_id(name,email)').order('created_at',{ascending:false});
    res.json(data||[]);
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// MARK DELIVERED - ketu behet komisioni
app.patch('/api/admin/purchases/:id', auth, admin, async (req,res) => {
  try {
    const { status } = req.body;

    const { data: sale } = await supabase.from('sales').select('*').eq('id',req.params.id).single();
    if(!sale) return res.status(404).json({ error:'Not found' });

    await supabase.from('sales').update({ status, bonus_paid: status==='delivered' }).eq('id',req.params.id);

    // Kreditoje komisionin VETEM kur delivered dhe nuk eshte paguar me pare
    if(status==='delivered' && !sale.bonus_paid) {
      const { data: buyer } = await supabase.from('users').select('parent_id').eq('id',sale.buyer_id).single();

      if(buyer?.parent_id) {
        // L1 - $100 te referrer
        await supabase.from('commissions').insert({
          from_user_id: sale.buyer_id,
          to_user_id:   buyer.parent_id,
          level: 1, amount: 100, type:'bonus', status:'paid'
        });
        await supabase.rpc('increment_wallet', { uid:buyer.parent_id, amount:100 });

        // L2 - $30 te grandparent
        const { data: parent } = await supabase.from('users').select('parent_id').eq('id',buyer.parent_id).single();
        if(parent?.parent_id) {
          await supabase.from('commissions').insert({
            from_user_id: sale.buyer_id,
            to_user_id:   parent.parent_id,
            level: 2, amount: 30, type:'bonus', status:'paid'
          });
          await supabase.rpc('increment_wallet', { uid:parent.parent_id, amount:30 });
        }
      }
    }

    res.json({ success:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// CHECK PURCHASE STATUS
app.get('/api/user/purchase-status', auth, async (req,res) => {
  try {
    const { data } = await supabase.from('sales')
      .select('id,status,created_at').eq('buyer_id',req.user.id)
      .order('created_at',{ascending:false}).limit(1).single();
    res.json({ purchased: !!data, status: data?.status||null });
  } catch(e) { res.json({ purchased:false, status:null }); }
});
app.listen(PORT, () => console.log(`GoldBot API on port ${PORT}`));
