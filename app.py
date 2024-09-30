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

username = ""


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
    rows = db.execute("SELECT * FROM assets WHERE username=?", username)
    for row in rows:
        symbol = row["symbol"]
        db.execute("UPDATE assets SET current_price=? WHERE symbol=?",
                   lookup(symbol)["price"], symbol)
    rows = db.execute(
        "SELECT *, b_num - s_num AS number, (b_num - s_num) * current_price AS value FROM assets WHERE username=?", username)
    cash = db.execute("SELECT * FROM users WHERE username=?", username)[0]["cash"]
    stock_assets = db.execute("SELECT SUM((b_num - s_num) * current_price) FROM assets WHERE username=?",
                              username)[0]["SUM((b_num - s_num) * current_price)"]
    if stock_assets == None:
        assets = float(cash)
    else:
        assets = float(stock_assets) + float(cash)
    return render_template("index.html", username=username, rows=rows,
                           cash=cash, assets=assets)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    if not request.form.get("shares").isnumeric():
        return apology("Enter integer number of shares", 400)
    if not request.form.get("symbol").isalpha():
        return apology("Enter a valid stock", 400)
    if lookup(request.form.get("symbol").upper()) == None:
        return apology("Stock does not exist", 400)
    # alert("breached the failsafe")
    symbol, number, balance, time, price, tot_price = get_info()
    if number < 1:
        return apology("Enter atleast one share", 400)
    if tot_price > balance:
        return apology("Not enough balance in your account", 400)
    update_cash(balance - tot_price)
    db.execute("INSERT INTO transactions (username, symbol, price, number, type, datetime) VALUES (?, ?, ?, ?, 'BUY', ?)",
               username, symbol, price, number, time)
    rows = db.execute("SELECT * FROM assets WHERE username=? AND symbol=?", username, symbol)
    if len(rows) == 1:
        b_num = rows[0]["b_num"]
        b_price = rows[0]["b_price"]
        db.execute("UPDATE assets SET b_num=?, b_price=? WHERE username=? AND symbol=?",
                   b_num + number, b_price + tot_price, username, symbol)
    else:
        db.execute("INSERT INTO assets (username, symbol, b_num, b_price) VALUES (?, ?, ?, ?)",
                   username, symbol, number, tot_price)
    return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        results = db.execute(
            "SELECT symbol FROM assets WHERE username=? AND b_num - s_num > 0", username)
        symbols = [row["symbol"] for row in results]
        return render_template("sell.html", symbols=symbols)

    symbol, number, balance, time, price, tot_price = get_info()
    rows = db.execute("SELECT * FROM assets WHERE username=? AND symbol=?", username, symbol)

    if len(rows) == 0:
        return apology("You do not own those shares", 40)
    b_num = rows[0]["b_num"]
    s_num = rows[0]["s_num"]
    s_price = rows[0]["s_price"]
    if b_num < number + s_num:
        return apology("You do not have these many shares", 400)

    db.execute("INSERT INTO transactions (username, symbol, price, number, type, datetime) VALUES (?, ?, ?, ?, 'SELL', ?)",
               username, symbol, price, number, time)
    db.execute("UPDATE assets SET s_num=?, s_price=? WHERE username=? AND symbol=?",
               number + s_num, s_price + tot_price, username, symbol)
    update_cash(balance + tot_price)
    return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT * FROM transactions WHERE username = ?", username)
    return render_template("history.html", username=username, history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    global username
    # Forget any user_id
    session.clear()
    username = ""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        username = request.form.get("username")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    global username
    # Forget any user_id
    session.clear()
    username = ""

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html", statement="")
    symbol = request.form.get("symbol")
    if symbol.isalpha():  # checks for letters
        results = lookup(symbol.upper())
        if results == None:
            return apology("Stock not found", 400)
        statement = "Showing results for: " + symbol
        return render_template("quote.html", statement=statement, results=results)
    else:
        return apology("Please Enter a Valid Stock Symbol", 400)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html", message="")
    else:
        username = request.form.get("username")
        password = request.form.get("password")

        if username == "" or password == "":
            return apology("Please enter a username", 400)
        confirmation = request.form.get("confirmation")
        if len(db.execute("SELECT * FROM users WHERE username=?", username)) != 0:
            return apology("Username not available", 400)
        elif password != confirmation:
            return apology("Passwords do not match", 400)
        hash = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                   username, hash)
        return redirect("/")


# helper functions-
def update_cash(new_total):
    db.execute("UPDATE users SET cash = ? WHERE username = ?", new_total, username)


def get_info():
    symbol = request.form.get("symbol").upper()
    number = int(request.form.get("shares"))
    balance = float(db.execute("SELECT cash FROM users WHERE username=?", username)[0]['cash'])
    time = str(datetime.now())
    price = lookup(symbol)["price"]
    tot_price = price * number
    return symbol, number, balance, time, price, tot_price
