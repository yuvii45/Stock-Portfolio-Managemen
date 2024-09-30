import os

from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    name = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]["username"]
    rows = db.execute("SELECT * FROM assets WHERE username=?", name)
    for row in rows:
        symbol = row["symbol"]
        db.execute("UPDATE assets SET current_price=? WHERE symbol=?",
                   lookup(symbol)["price"], symbol)
    rows = db.execute(
        "SELECT *, b_num - s_num AS number, (b_num - s_num) * current_price AS value FROM assets WHERE username=?", name)
    cash = db.execute("SELECT * FROM users WHERE username=?", name)[0]["cash"]
    return render_template("index.html", name=name, rows=rows, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    symbol = request.form.get("symbol")
    shares = int(request.form.get("shares"))
    id = session["user_id"]
    balance = float(db.execute("SELECT cash FROM users WHERE id=?", id)[0]['cash'])
    if lookup(symbol) == None:
        return apology("Symbol does not exist", 403)
    elif shares < 1:
        return apology("Enter atleast one share", 403)
    price = lookup(symbol)["price"]
    tot_price = price * shares
    if tot_price > balance:
        return apology("Not enough balance in your account", 403)
    db.execute("UPDATE users SET cash = ? WHERE id = ?", balance - tot_price, id)
    when = str(datetime.now())
    name = db.execute("SELECT username FROM users WHERE id=?", id)[0]['username']
    db.execute("INSERT INTO transactions (username, symbol, price, number, type, datetime) VALUES (?, ?, ?, ?, 'BUY', ?)",
               name, symbol, price, shares, when)
    rows = db.execute("SELECT * FROM assets WHERE username=? AND symbol=?", name, symbol)
    if len(rows) == 1:
        b_num = rows[0]["b_num"]
        b_price = rows[0]["b_price"]
        db.execute("UPDATE assets SET b_num=?, b_price=? WHERE username=? AND symbol=?",
                   b_num + shares, b_price + tot_price, name, symbol)
    else:
        db.execute("INSERT INTO assets (username, symbol, b_num, b_price) VALUES (?, ?, ?, ?)",
                   name, symbol, shares, tot_price)
    return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    name = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]["username"]
    history = db.execute("SELECT * FROM transactions WHERE username = ?", name)
    return render_template("history.html", name=name, history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        id = session["user_id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html", statement="")
    symbol = request.form.get("symbol").upper()
    results = lookup(symbol)
    statement = "Showing results for: " + symbol
    return render_template("quote.html", statement=statement, results=results)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html", message="")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmed_password = request.form.get("confirmed_password")
        if len(db.execute("SELECT * FROM users WHERE username=?", username)) != 0:
            return render_template("register.html", message="Username not available")
        elif password != confirmed_password:
            return render_template("register.html", message="Passwords did not match")
        hash = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                   username, hash)
        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        return render_template("sell.html")

    symbol = request.form.get("symbol")
    shares = int(request.form.get("shares"))
    name = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]["username"]
    price = lookup(symbol)["price"]
    tot_price = price * shares
    balance = float(db.execute("SELECT cash FROM users WHERE username=?", name)[0]['cash'])
    when = str(datetime.now())
    rows = db.execute("SELECT * FROM assets WHERE username=? AND symbol=?", name, symbol)

    if len(rows) == 0:
        return apology("You do not own those shares", 403)
    b_num = rows[0]["b_num"]
    s_num = rows[0]["s_num"]
    s_price = rows[0]["s_price"]
    if b_num < shares + s_num:
        return apology("You do not have these many shares", 403)

    db.execute("INSERT INTO transactions (username, symbol, price, number, type, datetime) VALUES (?, ?, ?, ?, 'SELL', ?)",
               name, symbol, price, shares, when)
    db.execute("UPDATE assets SET s_num=?, s_price=? WHERE username=? AND symbol=?",
               shares + s_num, s_price + tot_price, name, symbol)
    db.execute("UPDATE users SET cash=? WHERE username=?", balance + tot_price, name)

    return redirect("/")
