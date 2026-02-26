import os
import datetime
from urllib.parse import quote_plus
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
    UserMixin,
)
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-in-production")

# mongo setup
MONGO_DBNAME = os.getenv("MONGO_DBNAME", "events_nyu")
_mongo_host = os.getenv("MONGO_HOST")
_mongo_user = os.getenv("MONGO_USERNAME")
_mongo_pass = os.getenv("MONGO_PASSWORD")
if _mongo_host and _mongo_user and _mongo_pass:
    _encoded = quote_plus(_mongo_pass)
    if ".mongodb.net" in _mongo_host:
        MONGO_URI = f"mongodb+srv://{_mongo_user}:{_encoded}@{_mongo_host}/?retryWrites=true&w=majority"
    else:
        MONGO_URI = f"mongodb://{_mongo_user}:{_encoded}@{_mongo_host}:27017/"
else:
    MONGO_URI = os.getenv("MONGO_URI") or os.getenv("MONGODB_URI", "mongodb://localhost:27017")
connection = MongoClient(MONGO_URI, tlsAllowInvalidCertificates=True)
db = connection[MONGO_DBNAME]
users_coll = db.users
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = None


class User(UserMixin):
    def __init__(self, doc):
        self.id = str(doc["_id"])
        self.username = doc.get("username", "")
        self.name = doc.get("name", "")
        self.role = doc.get("role", "seeker")  # "seeker" | "organization"

    @staticmethod
    def get_by_username(username):
        doc = users_coll.find_one({"username": username.lower().strip()})
        return User(doc) if doc else None

    @staticmethod
    def create(username, password, name, role):
        username = username.lower().strip()
        if users_coll.find_one({"username": username}):
            return None
        doc = {
            "username": username,
            "password_hash": generate_password_hash(password),
            "name": (name or "").strip(),
            "role": role,
            "created_at": datetime.datetime.utcnow(),
        }
        ins = users_coll.insert_one(doc)
        doc["_id"] = ins.inserted_id
        return User(doc)


@login_manager.user_loader
def load_user(user_id):
    try:
        doc = users_coll.find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None
    return User(doc) if doc else None


EVENTS = [
    {"id": "1", "title": "Career Fair @ Tandon", "category": "Academic", "location": "Bobst Library",
    "datetime": "02/28 6:30 PM", "description": "Meet employers..."},
    {"id": "2", "title": "Jazz Night", "category": "Arts", "location": "Kimmel Center",
    "datetime": "03/01 2:00 PM", "description": "Live jazz..."},
    {"id": "3", "title": "Basketball Open Gym", "category": "Sports", "location": "Palladium Gym",
    "datetime": "03/02 8:00 PM", "description": "Bring your ID..."},
    {"id": "4", "title": "Campus Tour", "category": "Today", "location": "NYU Campus",
    "datetime": "Today 5:00 PM", "description": "Tour starts..."},
]

@app.route("/")
@login_required
def home():
    q = request.args.get("q", "").strip().lower()
    category = request.args.get("category", "All")

    events = EVENTS
    if q:
        events = [e for e in events if q in e["title"].lower()]
    if category != "All":
        events = [e for e in events if e["category"] == category]

    return render_template("events_list.html", events=events, q=q, category=category)

@app.route("/events/<event_id>")
@login_required
def event_detail(event_id):
    event = next((e for e in EVENTS if e["id"] == event_id), None)
    if not event:
        return "Event not found", 404
    return render_template("event_details.html", event=event)

@app.route("/profile")
@login_required
def profile():
    return "Profile page (TODO)"

@app.route("/dashboard")
@login_required
def dashboard():
    return "Dashboard page (TODO)"

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if not username or not password:
            flash("Please enter username and password.")
            return render_template("login.html")
        user = User.get_by_username(username)
        if not user:
            flash("Invalid username or password.")
            return render_template("login.html")
        doc = users_coll.find_one({"username": username.lower()})
        if not doc or not check_password_hash(doc["password_hash"], password):
            flash("Invalid username or password.")
            return render_template("login.html")
        login_user(user)
        next_url = request.args.get("next") or url_for("home")
        return redirect(next_url)
    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        role = request.form.get("role")
        if role not in ("seeker", "organization"):
            flash("Please choose whether you are a Student/Event Speaker or an Organization.")
            return render_template("signup.html")
        name = (request.form.get("name") or "").strip()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""
        if not name:
            flash("Please enter your name.")
            return render_template("signup.html")
        if not username:
            flash("Please enter email/username.")
            return render_template("signup.html")
        if not password:
            flash("Please enter a password.")
            return render_template("signup.html")
        if password != password2:
            flash("Passwords do not match.")
            return render_template("signup.html")
        user = User.create(username, password, name, role)
        if not user:
            flash("That email/username is already registered.")
            return render_template("signup.html")
        login_user(user)
        return redirect(url_for("home"))
    return render_template("signup.html")


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/poster-post", methods=["GET","POST"])
@login_required
def poster_post():
    if request.method == "POST":
        new_event = {
            "id": str(len(EVENTS) + 1),
            "title": request.form["title"],
            "description": request.form["description"],
            "location": request.form["location"],
            "category": request.form["category"],
            "datetime": request.form["mm"] + "/" + request.form["dd"] + " " + request.form["time"],
        }
        EVENTS.append(new_event)
        return redirect("/dashboard")
    return render_template("poster_post.html")

@app.route("/posteredit/<event_id>", methods=["GET","POST"])
def poster_edit(event_id):
    event = next((e for e in EVENTS if e["id"] == event_id), None)
    if request.method == "POST":
        event["title"]=request.form["title"]
        event["description"]=request.form["description"]
        event["location"]=request.form["location"]
        event["category"]=request.form["category"]
        event["datetime"]=request.form["mm"]+"/"+ request.form["dd"] + " " + request.form["time"]
        return redirect("/dashboard")
    
    return render_template("poster_edit.html", event=event)

if __name__ == "__main__":
    app.run(debug=True)