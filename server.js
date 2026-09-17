const express = require("express");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET_IN_PRODUCTION";
const DB_FILE = process.env.DB_FILE || path.join(__dirname, "rusangu_health_shop.db");

const db = new sqlite3.Database(DB_FILE);
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function run(sql, params=[]) {
  return new Promise((resolve, reject) => db.run(sql, params, function(err) {
    if (err) reject(err); else resolve({id: this.lastID, changes: this.changes});
  }));
}
function get(sql, params=[]) {
  return new Promise((resolve, reject) => db.get(sql, params, (err,row) => err ? reject(err) : resolve(row)));
}
function all(sql, params=[]) {
  return new Promise((resolve, reject) => db.all(sql, params, (err,rows) => err ? reject(err) : resolve(rows)));
}

db.serialize(async () => {
  await run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT DEFAULT '',
    sku TEXT DEFAULT '',
    buying_price REAL NOT NULL DEFAULT 0,
    selling_price REAL NOT NULL DEFAULT 0,
    stock INTEGER NOT NULL DEFAULT 0,
    min_stock INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`CREATE TABLE IF NOT EXISTS sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    unit_price REAL NOT NULL,
    buying_price REAL NOT NULL,
    total REAL NOT NULL,
    profit REAL NOT NULL,
    sold_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(product_id) REFERENCES products(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS stock_in (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    unit_buying_price REAL NOT NULL,
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(product_id) REFERENCES products(id)
  )`);

  const admin = await get("SELECT id FROM users WHERE username=?", ["admin"]);
  if (!admin) {
    const hash = await bcrypt.hash("1234", 10);
    await run("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)", ["admin", hash, "admin"]);
  }
});

function auth(req,res,next) {
  const token = (req.headers.authorization || "").replace("Bearer ","");
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({error:"Please log in again."}); }
}

app.post("/api/login", async (req,res) => {
  try {
    const {username,password} = req.body;
    const user = await get("SELECT * FROM users WHERE username=?", [username]);
    if (!user || !(await bcrypt.compare(password || "", user.password_hash)))
      return res.status(401).json({error:"Invalid username or password."});
    const token = jwt.sign({id:user.id,username:user.username,role:user.role}, JWT_SECRET,{expiresIn:"12h"});
    res.json({token,username:user.username,role:user.role});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.get("/api/dashboard", auth, async (req,res) => {
  try {
    const products = await all("SELECT * FROM products ORDER BY name");
    const low = products.filter(p => p.stock <= p.min_stock);
    const today = await get(`SELECT COALESCE(SUM(total),0) sales, COALESCE(SUM(profit),0) profit, COALESCE(SUM(quantity),0) items
      FROM sales WHERE date(sold_at,'localtime')=date('now','localtime')`);
    const totalProducts = await get("SELECT COUNT(*) c FROM products");
    const stockValue = await get("SELECT COALESCE(SUM(stock*buying_price),0) v FROM products");
    res.json({today, totalProducts:totalProducts.c, stockValue:stockValue.v, lowStock:low, products});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.get("/api/products", auth, async (req,res) => {
  res.json(await all("SELECT * FROM products ORDER BY name"));
});

app.post("/api/products", auth, async (req,res) => {
  try {
    const p=req.body;
    if(!p.name) return res.status(400).json({error:"Product name is required."});
    const r=await run(`INSERT INTO products(name,category,sku,buying_price,selling_price,stock,min_stock)
      VALUES(?,?,?,?,?,?,?)`,
      [p.name,p.category||"",p.sku||"",Number(p.buying_price)||0,Number(p.selling_price)||0,Number(p.stock)||0,Number(p.min_stock)||0]);
    res.json(await get("SELECT * FROM products WHERE id=?",[r.id]));
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.put("/api/products/:id", auth, async (req,res) => {
  try {
    const p=req.body;
    await run(`UPDATE products SET name=?,category=?,sku=?,buying_price=?,selling_price=?,min_stock=? WHERE id=?`,
      [p.name,p.category||"",p.sku||"",Number(p.buying_price)||0,Number(p.selling_price)||0,Number(p.min_stock)||0,req.params.id]);
    res.json(await get("SELECT * FROM products WHERE id=?",[req.params.id]));
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.delete("/api/products/:id", auth, async (req,res) => {
  try {
    const sales=await get("SELECT COUNT(*) c FROM sales WHERE product_id=?",[req.params.id]);
    if(sales.c) return res.status(400).json({error:"This product has sales history and cannot be deleted. Edit it instead."});
    await run("DELETE FROM stock_in WHERE product_id=?",[req.params.id]);
    await run("DELETE FROM products WHERE id=?",[req.params.id]);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.post("/api/sales", auth, async (req,res) => {
  try {
    const {product_id,quantity,unit_price}=req.body;
    const qty=Number(quantity);
    if(!product_id || !Number.isInteger(qty) || qty<=0) return res.status(400).json({error:"Enter a valid quantity."});
    const p=await get("SELECT * FROM products WHERE id=?",[product_id]);
    if(!p) return res.status(404).json({error:"Product not found."});
    if(p.stock < qty) return res.status(400).json({error:`Not enough stock. Available: ${p.stock}.`});
    const price=unit_price===undefined || unit_price==="" ? p.selling_price : Number(unit_price);
    const total=price*qty, profit=(price-p.buying_price)*qty;
    await run("BEGIN TRANSACTION");
    try {
      await run("UPDATE products SET stock=stock-? WHERE id=?",[qty,p.id]);
      await run(`INSERT INTO sales(product_id,quantity,unit_price,buying_price,total,profit) VALUES(?,?,?,?,?,?)`,
        [p.id,qty,price,p.buying_price,total,profit]);
      await run("COMMIT");
    } catch(e){ await run("ROLLBACK"); throw e; }
    res.json({message:"Sale recorded.",product:await get("SELECT * FROM products WHERE id=?",[p.id]),total,profit});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.post("/api/stock-in", auth, async (req,res) => {
  try {
    const {product_id,quantity,unit_buying_price}=req.body;
    const qty=Number(quantity), price=Number(unit_buying_price);
    if(!product_id || !Number.isInteger(qty) || qty<=0) return res.status(400).json({error:"Enter a valid quantity."});
    const p=await get("SELECT * FROM products WHERE id=?",[product_id]);
    if(!p) return res.status(404).json({error:"Product not found."});
    await run("BEGIN TRANSACTION");
    try {
      await run("UPDATE products SET stock=stock+?, buying_price=? WHERE id=?",[qty,price>=0?price:p.buying_price,p.id]);
      await run("INSERT INTO stock_in(product_id,quantity,unit_buying_price) VALUES(?,?,?)",[p.id,qty,price>=0?price:p.buying_price]);
      await run("COMMIT");
    } catch(e){ await run("ROLLBACK"); throw e; }
    res.json({message:"Stock received.",product:await get("SELECT * FROM products WHERE id=?",[p.id])});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.get("/api/sales", auth, async (req,res) => {
  const date=req.query.date || new Date().toISOString().slice(0,10);
  const rows=await all(`SELECT sales.*, products.name product_name FROM sales
    JOIN products ON products.id=sales.product_id
    WHERE date(sales.sold_at,'localtime')=? ORDER BY sales.id DESC`,[date]);
  const total=rows.reduce((a,r)=>a+r.total,0), profit=rows.reduce((a,r)=>a+r.profit,0);
  res.json({date,rows,total,profit});
});

app.get("/api/stock-in", auth, async (req,res) => {
  res.json(await all(`SELECT stock_in.*,products.name product_name FROM stock_in
    JOIN products ON products.id=stock_in.product_id ORDER BY stock_in.id DESC LIMIT 200`));
});

app.get("/api/reports/monthly", auth, async (req,res) => {
  const month=req.query.month || new Date().toISOString().slice(0,7);
  const rows=await all(`SELECT date(sold_at,'localtime') day, SUM(total) sales, SUM(profit) profit, SUM(quantity) items
    FROM sales WHERE strftime('%Y-%m',sold_at,'localtime')=? GROUP BY day ORDER BY day`,[month]);
  res.json({month,rows});
});

const INDEX_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rusangu Health Shop</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:#f4f6f8;color:#17212b}
header{background:#0d5c4b;color:white;padding:14px 18px;display:flex;justify-content:space-between;align-items:center}
header h1{font-size:20px;margin:0}.wrap{display:flex;min-height:calc(100vh - 56px)}
nav{width:220px;background:#fff;border-right:1px solid #ddd;padding:12px}.navbtn{display:block;width:100%;padding:12px;border:0;background:transparent;text-align:left;border-radius:8px;margin-bottom:4px;cursor:pointer;font-size:15px}.navbtn.active,.navbtn:hover{background:#e6f4f0;color:#0d5c4b;font-weight:bold}
main{flex:1;padding:20px;max-width:1300px;margin:auto;width:100%}.page{display:none}.page.active{display:block}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.card{background:#fff;padding:18px;border-radius:12px;border:1px solid #e1e5e8}.card small{color:#667}.card strong{display:block;font-size:25px;margin-top:8px}
.panel{background:#fff;padding:18px;border-radius:12px;border:1px solid #e1e5e8;margin-top:18px}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}
input,select,button{font:inherit}input,select{width:100%;padding:10px;border:1px solid #cdd4d8;border-radius:7px}.formrow{margin-bottom:12px}.formrow label{display:block;font-size:13px;font-weight:bold;margin-bottom:5px}
.btn{background:#0d5c4b;color:white;border:0;border-radius:7px;padding:10px 14px;cursor:pointer}.btn.secondary{background:#e8ecee;color:#17212b}.btn.danger{background:#b42318}
table{width:100%;border-collapse:collapse;margin-top:12px}th,td{padding:10px;border-bottom:1px solid #e5e7e9;text-align:left;font-size:14px}th{background:#f6f7f8}
.low{color:#b42318;font-weight:bold}.ok{color:#18794e;font-weight:bold}.toolbar{display:flex;gap:10px;align-items:end;flex-wrap:wrap}.toolbar>div{min-width:160px}
.notice{padding:10px;border-radius:7px;margin-bottom:10px}.notice.error{background:#fdecea;color:#9b1c13}.notice.success{background:#e8f5ee;color:#17663f}
#login{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0d5c4b}.loginbox{background:white;width:min(390px,92%);padding:28px;border-radius:14px}.loginbox h2{margin-top:0;color:#0d5c4b}.muted{color:#68737a;font-size:13px}
@media(max-width:850px){.cards{grid-template-columns:repeat(2,1fr)}nav{width:180px}.grid{grid-template-columns:1fr}}
@media(max-width:600px){.wrap{display:block}nav{width:100%;display:flex;overflow:auto;border-right:0;border-bottom:1px solid #ddd}.navbtn{min-width:120px}.cards{grid-template-columns:1fr 1fr}main{padding:12px}table{font-size:12px}.hide-mobile{display:none}}
</style>
</head>
<body>
<div id="login">
 <div class="loginbox">
  <h2>Rusangu Health Shop</h2>
  <p class="muted">Stock, sales and profit management</p>
  <div id="loginMsg"></div>
  <div class="formrow"><label>Username</label><input id="username" value="admin"></div>
  <div class="formrow"><label>Password</label><input id="password" type="password" value="1234"></div>
  <button class="btn" style="width:100%" onclick="login()">Sign in</button>
  <p class="muted">First login: admin / 1234. Change the password before production use.</p>
 </div>
</div>

<div id="app" style="display:none">
<header><h1>Rusangu Health Shop</h1><button class="btn secondary" onclick="logout()">Log out</button></header>
<div class="wrap">
<nav>
 <button class="navbtn active" data-page="dashboard">Dashboard</button>
 <button class="navbtn" data-page="products">Products</button>
 <button class="navbtn" data-page="sell">Record Sale</button>
 <button class="navbtn" data-page="stockin">Stock In</button>
 <button class="navbtn" data-page="sales">Daily Sales</button>
 <button class="navbtn" data-page="reports">Reports</button>
</nav>
<main>
<section id="dashboard" class="page active">
<h2>Dashboard</h2><div id="dashMsg"></div>
<div class="cards">
 <div class="card"><small>Today's Sales</small><strong id="dSales">K0.00</strong></div>
 <div class="card"><small>Today's Profit</small><strong id="dProfit">K0.00</strong></div>
 <div class="card"><small>Items Sold</small><strong id="dItems">0</strong></div>
 <div class="card"><small>Stock Value</small><strong id="dStock">K0.00</strong></div>
</div>
<div class="panel"><h3>Low Stock Alerts</h3><div id="lowStock"></div></div>
</section>

<section id="products" class="page">
<h2>Products</h2>
<div class="panel">
<h3>Add Product</h3>
<div class="grid">
<div class="formrow"><label>Product name</label><input id="pname"></div>
<div class="formrow"><label>Category</label><input id="pcat" placeholder="Cosmetics / Medicine"></div>
<div class="formrow"><label>SKU / code</label><input id="psku"></div>
<div class="formrow"><label>Buying price (K)</label><input id="pbuy" type="number" step="0.01"></div>
<div class="formrow"><label>Selling price (K)</label><input id="psell" type="number" step="0.01"></div>
<div class="formrow"><label>Opening stock</label><input id="pstock" type="number"></div>
<div class="formrow"><label>Minimum stock</label><input id="pmin" type="number" value="5"></div>
</div><button class="btn" onclick="addProduct()">Save Product</button>
</div>
<div class="panel"><h3>Current Stock</h3><div style="overflow:auto"><table><thead><tr><th>Product</th><th>Category</th><th>Buy</th><th>Sell</th><th>Stock</th><th>Min</th><th>Status</th></tr></thead><tbody id="productRows"></tbody></table></div></div>
</section>

<section id="sell" class="page">
<h2>Record Sale</h2><div id="saleMsg"></div>
<div class="panel">
<div class="grid">
<div class="formrow"><label>Product</label><select id="saleProduct" onchange="showSalePrice()"></select></div>
<div class="formrow"><label>Quantity</label><input id="saleQty" type="number" min="1" value="1" onchange="showSalePrice()"></div>
<div class="formrow"><label>Selling price per item (K)</label><input id="salePrice" type="number" step="0.01"></div>
<div class="formrow"><label>Total sale (K)</label><input id="saleTotal" readonly></div>
</div>
<button class="btn" onclick="recordSale()">Record Sale</button>
</div>
<div class="panel"><b>Automatic calculation:</b> stock decreases immediately, today's sales increase immediately, and profit is calculated from buying price.</div>
</section>

<section id="stockin" class="page">
<h2>Receive Stock</h2><div id="stockMsg"></div>
<div class="panel">
<div class="grid">
<div class="formrow"><label>Product</label><select id="stockProduct"></select></div>
<div class="formrow"><label>Quantity received</label><input id="stockQty" type="number" min="1"></div>
<div class="formrow"><label>New buying price per item (K)</label><input id="stockBuy" type="number" step="0.01"></div>
</div>
<button class="btn" onclick="receiveStock()">Add Stock</button>
</div>
</section>

<section id="sales" class="page">
<h2>Daily Sales</h2>
<div class="panel">
<div class="toolbar"><div><label>Date</label><input id="salesDate" type="date"></div><button class="btn" onclick="loadSales()">View</button></div>
<div id="salesSummary"></div><div style="overflow:auto"><table><thead><tr><th>Time</th><th>Product</th><th>Qty</th><th>Unit price</th><th>Total</th><th>Profit</th></tr></thead><tbody id="salesRows"></tbody></table></div>
</div>
</section>

<section id="reports" class="page">
<h2>Monthly Report</h2>
<div class="panel">
<div class="toolbar"><div><label>Month</label><input id="reportMonth" type="month"></div><button class="btn" onclick="loadReport()">View</button></div>
<div style="overflow:auto"><table><thead><tr><th>Date</th><th>Items sold</th><th>Sales</th><th>Profit</th></tr></thead><tbody id="reportRows"></tbody></table></div>
</div>
</section>
</main></div></div>

<script>
let token=localStorage.getItem("rhs_token"), products=[];
const K=n=>"K"+Number(n||0).toFixed(2);
async function api(url,opts={}){opts.headers=Object.assign({"Content-Type":"application/json"},opts.headers||{},token?{Authorization:"Bearer "+token}:{});const r=await fetch(url,opts);let d={};try{d=await r.json()}catch{}if(!r.ok)throw new Error(d.error||"Request failed");return d}
function msg(id,text,type="success"){document.getElementById(id).innerHTML=\`<div class="notice \${type}">\${text}</div>\`;setTimeout(()=>document.getElementById(id).innerHTML="",3500)}
async function login(){try{let d=await api("/api/login",{method:"POST",body:JSON.stringify({username:username.value,password:password.value})});token=d.token;localStorage.setItem("rhs_token",token);showApp()}catch(e){document.getElementById("loginMsg").innerHTML=\`<div class="notice error">\${e.message}</div>\`}}
function logout(){localStorage.removeItem("rhs_token");location.reload()}
function showApp(){document.getElementById("login").style.display="none";document.getElementById("app").style.display="block";loadAll()}
if(token) showApp();
document.querySelectorAll(".navbtn").forEach(b=>b.onclick=()=>{document.querySelectorAll(".navbtn").forEach(x=>x.classList.remove("active"));b.classList.add("active");document.querySelectorAll(".page").forEach(p=>p.classList.remove("active"));document.getElementById(b.dataset.page).classList.add("active");if(b.dataset.page==="sales")loadSales();if(b.dataset.page==="reports")loadReport()});
async function loadAll(){products=await api("/api/products");renderProducts();fillSelects();loadDashboard();salesDate.value=new Date().toISOString().slice(0,10);reportMonth.value=new Date().toISOString().slice(0,7)}
function renderProducts(){productRows.innerHTML=products.map(p=>\`<tr><td>\${esc(p.name)}</td><td>\${esc(p.category)}</td><td>\${K(p.buying_price)}</td><td>\${K(p.selling_price)}</td><td>\${p.stock}</td><td>\${p.min_stock}</td><td class="\${p.stock<=p.min_stock?'low':'ok'}">\${p.stock<=p.min_stock?'LOW STOCK':'OK'}</td></tr>\`).join("")||"<tr><td colspan=7>No products yet.</td></tr>"}
function fillSelects(){let opts=products.map(p=>\`<option value="\${p.id}">\${esc(p.name)} — Stock: \${p.stock}</option>\`).join("");saleProduct.innerHTML=opts;stockProduct.innerHTML=opts;showSalePrice()}
function showSalePrice(){let p=products.find(x=>x.id==saleProduct.value);if(!p)return;salePrice.value=p.selling_price;saleTotal.value=K(Number(saleQty.value||0)*Number(salePrice.value||0))}
saleQty.oninput=showSalePrice;salePrice.oninput=()=>saleTotal.value=K(Number(saleQty.value||0)*Number(salePrice.value||0));
async function addProduct(){try{let d=await api("/api/products",{method:"POST",body:JSON.stringify({name:pname.value,category:pcat.value,sku:psku.value,buying_price:pbuy.value,selling_price:psell.value,stock:pstock.value,min_stock:pmin.value})});msg("dashMsg","Product added.");["pname","pcat","psku","pbuy","psell","pstock"].forEach(x=>document.getElementById(x).value="");products=await api("/api/products");renderProducts();fillSelects();loadDashboard()}catch(e){msg("dashMsg",e.message,"error")}}
async function recordSale(){try{let d=await api("/api/sales",{method:"POST",body:JSON.stringify({product_id:saleProduct.value,quantity:saleQty.value,unit_price:salePrice.value})});msg("saleMsg",\`\${d.message} Total: \${K(d.total)} | Profit: \${K(d.profit)}\`);products=await api("/api/products");renderProducts();fillSelects();loadDashboard();saleQty.value=1;showSalePrice()}catch(e){msg("saleMsg",e.message,"error")}}
async function receiveStock(){try{let d=await api("/api/stock-in",{method:"POST",body:JSON.stringify({product_id:stockProduct.value,quantity:stockQty.value,unit_buying_price:stockBuy.value})});msg("stockMsg",d.message);products=await api("/api/products");renderProducts();fillSelects();loadDashboard();stockQty.value=""}catch(e){msg("stockMsg",e.message,"error")}}
async function loadDashboard(){try{let d=await api("/api/dashboard");dSales.textContent=K(d.today.sales);dProfit.textContent=K(d.today.profit);dItems.textContent=d.today.items;dStock.textContent=K(d.stockValue);lowStock.innerHTML=d.lowStock.length?d.lowStock.map(p=>\`<div class="notice error"><b>\${esc(p.name)}</b>: \${p.stock} left (minimum \${p.min_stock})</div>\`).join(""):"<div class='notice success'>No low-stock products.</div>"}catch(e){if(e.message.includes("log in"))logout()}}
async function loadSales(){try{let d=await api("/api/sales?date="+salesDate.value);salesSummary.innerHTML=\`<p><b>Sales:</b> \${K(d.total)} &nbsp; <b>Profit:</b> \${K(d.profit)}</p>\`;salesRows.innerHTML=d.rows.map(r=>\`<tr><td>\${new Date(r.sold_at).toLocaleTimeString()}</td><td>\${esc(r.product_name)}</td><td>\${r.quantity}</td><td>\${K(r.unit_price)}</td><td>\${K(r.total)}</td><td>\${K(r.profit)}</td></tr>\`).join("")||"<tr><td colspan=6>No sales for this date.</td></tr>"}catch(e){msg("dashMsg",e.message,"error")}}
async function loadReport(){try{let d=await api("/api/reports/monthly?month="+reportMonth.value);reportRows.innerHTML=d.rows.map(r=>\`<tr><td>\${r.day}</td><td>\${r.items}</td><td>\${K(r.sales)}</td><td>\${K(r.profit)}</td></tr>\`).join("")||"<tr><td colspan=4>No sales for this month.</td></tr>"}catch(e){msg("dashMsg",e.message,"error")}}
function esc(s){return String(s??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[m]))}
</script>
</body>
</html>`;
app.get("*",(req,res)=>res.type("html").send(INDEX_HTML));
app.listen(PORT,()=>console.log(`Rusangu Health Shop running on port ${PORT}`));
