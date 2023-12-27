import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
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
    cash = db.execute("SELECT * FROM users WHERE id == ?", session["user_id"])
    cash = round(cash[0].get("cash"), 2)
    totalCash = 0
    if not cash:
        return apology("User's cash invalid", cash=usd(cash))
    transactions = db.execute(
        "SELECT * FROM user_transactions WHERE user_id == ?", session["user_id"]
    )
    for i in range(len(transactions)):
        currentStockPrice = round(lookup(transactions[i]["symbol"])["price"], 2)
        total = currentStockPrice * transactions[i]["amount"]
        transactions[i]["total"] = usd(total)
        transactions[i]["currentPrice"] = usd(currentStockPrice)
        totalCash += currentStockPrice * transactions[i]["amount"]
    totalCash = round(totalCash, 2)
    return render_template(
        "index.html",
        transactions=transactions,
        cash=usd(cash),
        totalValue=usd(totalCash + cash),
    )


def is_integer_like(n):
    try:
        n = float(n)
    except ValueError:
        return False
    try:
        return n == int(n)
    except (ValueError, TypeError):
        return False


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    cash = db.execute("SELECT * FROM users WHERE id == ?", session["user_id"])
    cash = round(float(cash[0].get("cash")), 2)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        amount = request.form.get("shares")
        if symbol and amount:
            if not is_integer_like(amount):
                return apology("Invalid amount", cash=usd(cash))
            if int(float(amount)) < 0:
                return apology("Invalid amount", cash=usd(cash))
            symbol_stats = lookup(symbol)
            # print(symbol_stats)
            if symbol_stats:
                stock_price = int(float(symbol_stats["price"]))
                total_cost = float(stock_price) * int(float(amount))
                if not total_cost > 0:
                    return apology("Invalid amount(2)", cash=usd(cash))
                userData = db.execute(
                    "SELECT * FROM users WHERE id == ?", session["user_id"]
                )
                # print(userData[0])
                subtractAmount = str(float(userData[0]["cash"]) - total_cost)
                if float(userData[0]["cash"]) >= total_cost:
                    db.execute(
                        "UPDATE users SET cash = ? WHERE id == ?",
                        subtractAmount,
                        session["user_id"],
                    )

                    values = db.execute(
                        "SELECT * FROM user_transactions WHERE user_id == ? AND symbol == ?",
                        session["user_id"],
                        symbol,
                    )
                    if len(values) > 0:
                        new_stock_amount = int(float(values[0]["amount"])) + int(
                            float(amount)
                        )
                        db.execute(
                            "UPDATE user_transactions SET amount = ? WHERE user_id == ? AND symbol == ?",
                            int(float(new_stock_amount)),
                            session["user_id"],
                            symbol,
                        )
                    else:
                        db.execute(
                            "INSERT INTO user_transactions (user_id, symbol, amount, date_purchased, price_at_purchase) VALUES(?, ?, ?, ?, ?)",
                            session["user_id"],
                            symbol,
                            int(float(amount)),
                            datetime.now().strftime("%m/%d/%Y"),
                            usd(stock_price),
                        )

                    db.execute(
                        "INSERT INTO transactions (user_id, symbol, shares, transaction_type, price, time) VALUES(?, ?, ?, ?, ?, ?)",
                        session["user_id"],
                        symbol,
                        int(float(amount)),
                        "buy",
                        usd(lookup(symbol)["price"]),
                        datetime.now().strftime("%m/%d/%Y"),
                    )
                    return redirect("/")
                else:
                    return apology("Costs too much!", cash=usd(cash))
            else:
                return apology("Invalid Symbol", cash=usd(cash))
        else:
            return apology("Invalid Stock Symbol/Amount", cash=usd(cash))
    else:
        return render_template("buy.html", cash=usd(cash))


@app.route("/history")
@login_required
def history():
    cash = db.execute("SELECT * FROM users WHERE id == ?", session["user_id"])
    cash = round(cash[0].get("cash"), 2)
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT * FROM transactions WHERE user_id == ?", session["user_id"]
    )
    return render_template("history.html", transactions=transactions, cash=usd(cash))


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
    cash = db.execute("SELECT * FROM users WHERE id == ?", session["user_id"])
    cash = round(cash[0].get("cash"), 2)
    """Get stock quote."""
    if request.method == "POST":
        stock_symbol = request.form.get("symbol")
        if stock_symbol:
            stock_data = lookup(stock_symbol)
            if stock_data:
                return render_template(
                    "quoted.html",
                    cash=usd(cash),
                    name=stock_data["name"],
                    price=usd(stock_data["price"]),
                    symbol=stock_data["symbol"],
                )
            else:
                return apology("Invalid Stock Symbol", cash=usd(cash))
        else:
            return apology("Blank Input", cash=usd(cash))
    else:
        return render_template("quote.html", cash=usd(cash))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if username and password and confirmation:
            if password == confirmation:
                currentUser = db.execute(
                    "SELECT username FROM users WHERE username == ?", username
                )
                if len(currentUser) == 0:
                    db.execute(
                        "INSERT INTO users (username, hash) VALUES(?, ?)",
                        username,
                        generate_password_hash(password),
                    )
                    return render_template("login.html")
                else:
                    return apology("Invalid Username")
            else:
                return apology("Password Incorrect Repeat")
        else:
            return apology("Bad Username/Password")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    cash = db.execute("SELECT * FROM users WHERE id == ?", session["user_id"])
    cash = round(cash[0].get("cash"), 2)
    if request.method == "POST":
        stock = request.form.get("symbol")
        shares = request.form.get("shares")
        if stock and shares:
            stockData = lookup(stock)
            if not stockData:
                return apology("Invalid Stock Symbol", cash=usd(cash))
            if int(shares) > 0:
                values = db.execute(
                    "SELECT * FROM user_transactions WHERE user_id == ? AND symbol == ?",
                    session["user_id"],
                    stock,
                )
                if not values:
                    return apology("Invalid amount of shares", cash=usd(cash))
                if int(values[0]["amount"]) - int(shares) >= 0:
                    if int(values[0]["amount"]) - int(shares) == 0:
                        db.execute(
                            "DELETE FROM user_transactions WHERE user_id == ? AND symbol == ?",
                            session["user_id"],
                            stock,
                        )
                    else:
                        db.execute(
                            "UPDATE user_transactions SET amount = ? WHERE user_id == ? AND symbol == ?",
                            int(values[0]["amount"]) - int(shares),
                            session["user_id"],
                            stock,
                        )
                    stock_value = round((float(stockData["price"]) * int(shares)), 2)
                    if not stock_value >= 0:
                        return apology("Invalid stock price/amount", cash=usd(cash))
                    currentCash = db.execute(
                        "SELECT cash FROM users WHERE id == ?", session["user_id"]
                    )[0]["cash"]
                    db.execute(
                        "UPDATE users SET cash = ? WHERE id == ?",
                        round(currentCash + stock_value, 2),
                        session["user_id"],
                    )
                    db.execute(
                        "INSERT INTO transactions (user_id, symbol, shares, transaction_type, price, time) VALUES(?, ?, ?, ?, ?, ?)",
                        session["user_id"],
                        stock,
                        shares,
                        "sell",
                        usd(lookup(stock)["price"]),
                        datetime.now().strftime("%m/%d/%Y"),
                    )
                    return redirect("/")
                else:
                    return apology("Invalid Amount (2)", cash=usd(cash))
            else:
                return apology("Invalid Amount", cash=usd(cash))
        else:
            return apology("Invalid stock/amount", cash=usd(cash))

    else:
        stocks = db.execute(
            "SELECT symbol FROM user_transactions WHERE user_id == ?",
            session["user_id"],
        )
        return render_template("sell.html", stocks=stocks, cash=usd(cash))
    """Sell shares of stock"""


@app.route("/fund", methods=["GET", "POST"])
@login_required
def fund():
    cash = db.execute("SELECT * FROM users WHERE id == ?", session["user_id"])
    cash = round(float(cash[0].get("cash")), 2)
    if request.method == "POST":
        amount = round(float(request.form.get("amount")), 2)
        if amount:
            db.execute(
                "UPDATE users SET cash = ? WHERE id == ?",
                str(round(cash + amount, 2)),
                session["user_id"],
            )
            db.execute(
                "INSERT INTO transactions (user_id, symbol, shares, price, transaction_type, time) VALUES(?, ?, ?, ?, ?, ?)",
                session["user_id"],
                "NULL",
                0,
                str(usd(round(amount, 2))),
                "fund",
                datetime.now().strftime("%m/%d/%Y"),
            )
            return redirect("/")
        else:
            return apology("Invalid Amount", cash=usd(cash))
    else:
        return render_template("fund.html", cash=usd(cash))
