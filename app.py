import json, os, re, sqlite3
from datetime import datetime
from functools import wraps
from html import escape as esc
from flask import Flask, g, jsonify, request, session, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "gadgethub.db")
app = Flask(__name__, static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, pw TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, price INTEGER, j TEXT);
CREATE TABLE IF NOT EXISTS cart(user_id INTEGER, product_id INTEGER, qty INTEGER, PRIMARY KEY(user_id, product_id));
CREATE TABLE IF NOT EXISTS wish(user_id INTEGER, product_id INTEGER, PRIMARY KEY(user_id, product_id));
CREATE TABLE IF NOT EXISTS alerts(user_id INTEGER, product_id INTEGER, PRIMARY KEY(user_id, product_id));
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INTEGER, total INTEGER, address TEXT, payment TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS order_items(order_id INTEGER, product_id INTEGER, name TEXT, price INTEGER, qty INTEGER);
"""


def init_db():
    c = sqlite3.connect(DB)
    c.executescript(SCHEMA)
    with open(os.path.join(BASE, "products.json"), encoding="utf-8") as f:
        for p in json.load(f):
            c.execute("INSERT OR REPLACE INTO products(id, price, j) VALUES(?,?,?)",
                      (p["id"], p["p"], json.dumps(p, ensure_ascii=False)))
    c.commit()
    c.close()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def now():
    return datetime.now().strftime("%d %b %Y, %I:%M %p")


def inr(n):
    s = str(int(round(n)))
    if len(s) > 3:
        s = re.sub(r"(\d)(?=(\d\d)+$)", r"\1,", s[:-3]) + "," + s[-3:]
    return "₹" + s


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **k):
        if "uid" not in session:
            return jsonify(error="Pehle login karo"), 401
        return fn(*a, **k)
    return wrapper


@app.get("/")
def home():
    return send_from_directory("static", "index.html")


@app.post("/api/register")
def register():
    d = request.get_json(silent=True) or {}
    name = (d.get("name") or "").strip()
    email = (d.get("email") or "").strip().lower()
    pw = d.get("password") or ""
    if len(name) < 2 or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) or len(pw) < 6:
        return jsonify(error="Naam, sahi email aur 6+ character ka password do"), 400
    try:
        cur = db().execute("INSERT INTO users(name, email, pw, created) VALUES(?,?,?,?)",
                           (name, email, generate_password_hash(pw), now()))
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Ye email pehle se registered hai"), 400
    session["uid"] = cur.lastrowid
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    u = db().execute("SELECT * FROM users WHERE email=?", ((d.get("email") or "").strip().lower(),)).fetchone()
    if not u or not check_password_hash(u["pw"], d.get("password") or ""):
        return jsonify(error="Email ya password galat hai"), 401
    session["uid"] = u["id"]
    return jsonify(ok=True)


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    u = db().execute("SELECT id, name, email FROM users WHERE id=?", (session.get("uid"),)).fetchone()
    return jsonify(user=dict(u) if u else None)


@app.get("/api/products")
def products():
    return jsonify([json.loads(r["j"]) for r in db().execute("SELECT j FROM products ORDER BY id")])


def ids(table):
    return [r[0] for r in db().execute(f"SELECT product_id FROM {table} WHERE user_id=?", (session["uid"],))]


def cart_map():
    return {str(r[0]): r[1] for r in db().execute(
        "SELECT product_id, qty FROM cart WHERE user_id=?", (session["uid"],))}


@app.get("/api/state")
@login_required
def state():
    return jsonify(wish=ids("wish"), alerts=ids("alerts"), cart=cart_map())


def toggle(table, pid):
    q, uid = db(), session["uid"]
    if not q.execute("SELECT 1 FROM products WHERE id=?", (pid,)).fetchone():
        abort(404)
    if q.execute(f"SELECT 1 FROM {table} WHERE user_id=? AND product_id=?", (uid, pid)).fetchone():
        q.execute(f"DELETE FROM {table} WHERE user_id=? AND product_id=?", (uid, pid))
    else:
        q.execute(f"INSERT INTO {table}(user_id, product_id) VALUES(?,?)", (uid, pid))
    q.commit()
    return jsonify({table: ids(table)})


@app.post("/api/wish/<int:pid>")
@login_required
def wish(pid):
    return toggle("wish", pid)


@app.post("/api/alert/<int:pid>")
@login_required
def alert(pid):
    return toggle("alerts", pid)


@app.post("/api/cart")
@login_required
def cart_change():
    d = request.get_json(silent=True) or {}
    try:
        pid, delta = int(d["id"]), int(d["delta"])
    except (KeyError, ValueError, TypeError):
        return jsonify(error="Galat request"), 400
    q, uid = db(), session["uid"]
    if not q.execute("SELECT 1 FROM products WHERE id=?", (pid,)).fetchone():
        return jsonify(error="Product nahi mila"), 404
    row = q.execute("SELECT qty FROM cart WHERE user_id=? AND product_id=?", (uid, pid)).fetchone()
    qty = min(10, (row["qty"] if row else 0) + delta)
    if qty <= 0:
        q.execute("DELETE FROM cart WHERE user_id=? AND product_id=?", (uid, pid))
    else:
        q.execute("INSERT OR REPLACE INTO cart(user_id, product_id, qty) VALUES(?,?,?)", (uid, pid, qty))
    q.commit()
    return jsonify(cart=cart_map())


@app.delete("/api/cart/<int:pid>")
@login_required
def cart_remove(pid):
    db().execute("DELETE FROM cart WHERE user_id=? AND product_id=?", (session["uid"], pid))
    db().commit()
    return jsonify(cart=cart_map())


@app.post("/api/checkout")
@login_required
def checkout():
    d = request.get_json(silent=True) or {}
    address = (d.get("address") or "").strip()
    payment = d.get("payment") if d.get("payment") in ("Cash on Delivery", "UPI (demo)", "Card (demo)") else "Cash on Delivery"
    if len(address) < 5:
        return jsonify(error="Delivery address likho"), 400
    q, uid = db(), session["uid"]
    rows = q.execute("SELECT c.product_id, c.qty, p.price, p.j FROM cart c JOIN products p ON p.id=c.product_id "
                     "WHERE c.user_id=?", (uid,)).fetchall()
    if not rows:
        return jsonify(error="Cart khali hai"), 400
    total = sum(r["price"] * r["qty"] for r in rows)
    oid = q.execute("INSERT INTO orders(user_id, total, address, payment, created) VALUES(?,?,?,?,?)",
                    (uid, total, address, payment, now())).lastrowid
    for r in rows:
        q.execute("INSERT INTO order_items VALUES(?,?,?,?,?)",
                  (oid, r["product_id"], json.loads(r["j"])["n"], r["price"], r["qty"]))
    q.execute("DELETE FROM cart WHERE user_id=?", (uid,))
    q.commit()
    return jsonify(id=oid, total=total)


@app.get("/api/orders")
@login_required
def orders():
    rows = db().execute("SELECT id, total, created FROM orders WHERE user_id=? ORDER BY id DESC", (session["uid"],))
    return jsonify([dict(r) for r in rows])


@app.get("/bill/<int:oid>")
def bill(oid):
    if "uid" not in session:
        return "Pehle login karo", 401
    q = db()
    o = q.execute("SELECT o.*, u.name, u.email FROM orders o JOIN users u ON u.id=o.user_id "
                  "WHERE o.id=? AND o.user_id=?", (oid, session["uid"])).fetchone()
    if not o:
        abort(404)
    items = q.execute("SELECT * FROM order_items WHERE order_id=?", (oid,)).fetchall()
    rows = "".join(f"<tr><td>{esc(i['name'])}</td><td>{i['qty']}</td><td>{inr(i['price'])}</td>"
                   f"<td>{inr(i['price'] * i['qty'])}</td></tr>" for i in items)
    taxable = round(o["total"] / 1.18)
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Invoice GH-{oid:05d}</title><style>
body{{font-family:Verdana,sans-serif;max-width:700px;margin:20px auto;padding:0 14px;color:#1d1f24}}
h1{{margin:0;color:#0b6e4f}} table{{width:100%;border-collapse:collapse;margin:14px 0}}
th,td{{border-bottom:1px solid #ccc;padding:8px 4px;text-align:left}} .r{{text-align:right}}
button{{padding:10px 16px;margin:10px 0}} @media print{{.np{{display:none}}}}</style></head><body>
<h1>GadgetHub</h1><p>Tax Invoice · <b>GH-{oid:05d}</b><br>Date: {esc(o['created'])}</p>
<p><b>Billed to:</b> {esc(o['name'])} ({esc(o['email'])})<br><b>Address:</b> {esc(o['address'])}<br><b>Payment:</b> {esc(o['payment'])}</p>
<table><tr><th>Item</th><th>Qty</th><th>Price</th><th>Amount</th></tr>{rows}</table>
<p class="r">Taxable value: {inr(taxable)}<br>GST @18% (included): {inr(o['total'] - taxable)}<br>
<b style="font-size:18px">Grand Total: {inr(o['total'])}</b></p>
<p style="color:#666;font-size:12px">Ye demo project ka invoice hai.</p>
<button class="np" onclick="window.print()">🖨️ Print / Save as PDF</button></body></html>"""


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
