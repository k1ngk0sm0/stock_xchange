import os

from flask_sqlalchemy import SQLAlchemy
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import requests
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure SQLAlchemy Library to use SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///finance.db'

db = SQLAlchemy(app)

#Create users table
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, unique=True, nullable=False)
    pass_hash = db.Column(db.Text, nullable=False)
    cash = db.Column(db.Float, nullable=False, default=10000.00)

#Create stocks tables
class Transactions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(5), nullable=False)
    shares = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    transacted = db.Column(db.DateTime, default=datetime.now())
    owner = db.Column(db.Integer, nullable=False)

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

def portfolio():
        """
        Returns a list of dictionaries for stocks a users portfolio
        as well as their total assets
        """
        #Query transactions by user id
        trans = Transactions.query.filter_by(owner=session['user_id']).all()
        
        #Create list of comanies user owns stock in
        companies = []
        for t in trans:
            if t.symbol not in companies:
                companies.append(t.symbol)

        #Create list of current stock dictionaries and total their values
        total = 0
        stocks = []
        for company in companies:
            trans = Transactions.query.filter_by(owner=session['user_id'], symbol=company).all()
            stock = {}
            stock['shares'] = 0
            for t in trans:
                stock['shares'] += t.shares
            if stock['shares'] > 0:
                stock['symbol'] = company
                stock['name'] = lookup(company)['name']
                stock['price'] = lookup(company)['price']
                stock['total'] = stock['shares'] * stock['price']
                stock['price'] = usd(stock['price'])
                stock['total'] = usd(stock['total'])
                total += float(stock['total'][1:].replace(',', ''))
                stocks.append(stock)

        #Set user cash and total values
        value = {}
        value['cash'] = usd(Users.query.filter_by(id=session['user_id']).first().cash)
        value['total'] = usd(total + float(value['cash'][1:].replace(',', '')))

        #Add values to list
        stocks.append(value)

        #Return list of dictionaries
        return stocks

@app.route("/")
@login_required
def index():

    #Set stock and value variables
    stocks = []
    for i in portfolio():
        if 'cash' in i.keys():
            value = i
        else:
            stocks.append(i)

    #Return index.html
    return render_template('index.html', stocks=stocks, value=value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    
    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == 'GET':
        return render_template("buy.html")

    # User reached route via POST (as by submitting a form via POST)
    else:
        # Ensure input is valid
        if not lookup(request.form.get('symbol')):
            return apology("Invalid Symbol", 403)
        
        if not request.form.get('shares'):
            return apology('Enter Number of Shares', 403)
        
        # Try to store shares variable and continue input validation
        try:
            shares = int(request.form.get('shares'))
        except ValueError:
            return apology('Invalid Entry', 403)

        if shares <= 0:
            return apology("Shares Must Be Positive Number", 403)

        # Lookup stock and store stock variable
        stock = lookup(request.form.get('symbol'))

        # Ensure user has funds to buy
        user = Users.query.filter_by(id=session['user_id']).first()

        if user.cash < (stock['price'] * shares):
            return apology("Insufficient Funds", 400)

        # Add transaction to db
        trans = Transactions(symbol=request.form.get('symbol').upper(), shares=shares,
                             price=stock['price'], transacted=datetime.now(), owner=session['user_id'])
        db.session.add(trans)
        db.session.commit()

        # Update User's cash
        user.cash -= (trans.price * trans.shares)
        db.session.commit()

        # Redirect to home
        return redirect('/')
        
        
@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    #Query transactions by user id
    trans = Transactions.query.filter_by(owner=session['user_id']).all()

    #Convert Price to US Dollars and format transaction time
    for t in trans:
        t.price = usd(t.price)
        t.transacted = t.transacted.strftime('%Y-%m-%d %H:%M:%S')

    #Return history.html
    return render_template('history.html', trans=trans)


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
        rows = Users.query.filter_by(username=request.form.get("username")).all()
        
        # Ensure username exists and password is correct
        if len(rows) != 1:
            return apology("invalid username", 403)

        if not check_password_hash(rows[0].pass_hash, request.form.get('password')):
            return apology("invalid password", 404)
                

        # Remember which user has logged in
        session["user_id"] = rows[0].id

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

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == 'GET':
        return render_template("quote.html")

    # User reached route via POST (as by submitting a form via POST)
    else:

        #Ensure a valid symbol was entered
        if not lookup(request.form.get('symbol')):
            return apology('Not a valid symbol', 400)

        else:
            #Return stock value to user
            stock = lookup(request.form.get('symbol'))
            return render_template('quoted.html', symbol=stock['symbol'], company=stock['name'], price=usd(stock['price']))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure password was verified
        elif not request.form.get("password2"):
            return apology("must verify password", 403)
        
        # Query database for username
        rows = Users.query.filter_by(username=request.form.get('username')).all()

        #Ensure username isn't already in use
        if len(rows) != 0:
            return apology("username is already in use", 403)

        #Ensure passwords match
        if request.form.get('password') != request.form.get('password2'):
            return apology('passwords do not match')

        #Add user to database
        user = Users(username=request.form.get("username"), 
                     pass_hash=generate_password_hash(request.form.get("password")))
        db.session.add(user)
        db.session.commit()

        # Redirect user to login page
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    
    #Create list of stocks in users portfolio
    stocks = [s for s in portfolio() if 'symbol' in s.keys()]

    #User arrived via GET
    if request.method == 'GET':
        #Return sell.html
        return render_template('sell.html', stocks=stocks)

    #User arrived via POST
    else:
        if request.method == 'POST':

            #Set variable for selected stock
            stock = [s for s in stocks if s['symbol'] == request.form.get('symbol')][0]

            #Make sure user has enough stock to sell
            if int(request.form.get('shares')) > stock['shares']:
                return apology('too many shares', 400)

            else:
                #See what stock is currently selling for and store in variable
                price = lookup(stock['symbol'])['price']

                #Add transaction to history
                trans = Transactions(symbol=stock['symbol'].upper(), shares=(int(request.form.get('shares')) * -1), 
                                     price=price, transacted=datetime.now(), owner=session['user_id'])
                db.session.add(trans)
                db.session.commit()

                #update user's cash
                Users.query.filter_by(id=session['user_id']).first().cash += (price * int(request.form.get('shares')))
                db.session.commit()

                return redirect('/')


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

#Run file in debug mode
if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)