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
events_coll = db.events

def mongo_event_to_view(doc):
    doc = dict(doc)
    doc["id"] = str(doc["_id"])
    doc.pop("_id", None)

    org_name = None
    organizer_id = doc.get("organizer_user_id")

    if organizer_id:
        org = orgs_coll.find_one({"user_id": organizer_id})
        if org:
            org_name = org.get("name")

    doc["organizer_name"] = org_name or "Unknown Organizer"

    return doc

users_coll = db.users
orgs_coll = db.organizations
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
            "password_hash": generate_password_hash(password, method="pbkdf2:sha256"),
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

''' Dummy data for testing without MongoDB, uncomment if needed.
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
'''

@app.route("/")
@login_required
def home():
    q = request.args.get("q", "").strip().lower()
    category = request.args.get("category", "All")

    query = {}
    if q:
        query["title"] = {"$regex": q, "$options": "i"}  # case-insensitive search
    if category != "All":
        query["category"] = category

    docs = list(events_coll.find(query))
    events = [mongo_event_to_view(d) for d in docs]

    return render_template("events_list.html", events=events, q=q, category=category)

@app.route("/events/<event_id>")
@login_required
def event_detail(event_id):
    try:
        doc = events_coll.find_one({"_id": ObjectId(event_id)})
    except Exception:
        doc = None

    if not doc:
        return "Event not found", 404

    event = mongo_event_to_view(doc)
    return render_template("event_details.html", event=event)
@app.route("/profile")
@login_required
def profile():
    if current_user.role == "organization":
        docs = list(events_coll.find({"organizer_user_id": ObjectId(current_user.id)}))
    else:
        docs = list(events_coll.find().limit(2))

    events_to_show = [mongo_event_to_view(d) for d in docs]
    return render_template("profile.html", user=current_user, events=events_to_show)
@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role != "organization":
        return redirect(url_for("home"))

    docs = list(events_coll.find({"organizer_user_id": ObjectId(current_user.id)}))
    events = [mongo_event_to_view(d) for d in docs]
    return render_template("poster_dashboard.html", events=events)

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
        if user and role == "organization":
            orgs_coll.insert_one({
                "user_id": ObjectId(user.id),
                "name": name,
                "email": username.lower().strip(),
                "hosted_event_ids": [],
                "created_at": datetime.datetime.utcnow(),
            })
        if not user:
            flash("That email/username is already registered.")
            return render_template("signup.html")
        login_user(user)
        return redirect(url_for("home"))
    return render_template("signup.html")

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login")) # Fixed: redirect to login instead of home (which requires login)

@app.route("/poster-post", methods=["GET", "POST"])
@login_required
def poster_post():
    if current_user.role != "organization":
        flash("Only organizations can post events.")
        return redirect(url_for("home"))

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        location = (request.form.get("location") or "").strip()
        category = (request.form.get("category") or "").strip()
        mm = (request.form.get("mm") or "").strip()
        dd = (request.form.get("dd") or "").strip()
        time = (request.form.get("time") or "").strip()
        capacity = (request.form.get("capacity") or "").strip()

        if not title or not location or not category or not mm or not dd or not time:
            flash("Please fill out all required fields.")
            return render_template("poster_post.html")

        new_event = {
            "title": title,
            "description": description,
            "location": location,
            "category": category,
            "date": f"{mm}/{dd}",
            "time": time,
            "capacity": int(capacity) if capacity.isdigit() else None,

            "organizer_user_id": ObjectId(current_user.id),

            "rsvp_user_ids": [],

            "created_at": datetime.datetime.utcnow(),
        }

        ins = events_coll.insert_one(new_event)

        orgs_coll.update_one(
            {"user_id": ObjectId(current_user.id)},
            {"$addToSet": {"hosted_event_ids": ins.inserted_id}}
        )

        flash("Event posted!")
        return redirect(url_for("dashboard"))

    return render_template("poster_post.html")

@app.route("/posteredit/<event_id>", methods=["GET","POST"])
@app.route("/posteredit/<event_id>", methods=["GET","POST"])
@login_required
def poster_edit(event_id):
    try:
        oid = ObjectId(event_id)
    except Exception:
        return "Invalid event id", 400

    if request.method == "POST":
        events_coll.update_one(
            {"_id": oid},
            {"$set": {
                "title": request.form["title"].strip(),
                "description": request.form["description"].strip(),
                "location": request.form["location"].strip(),
                "category": request.form["category"].strip(),
                "datetime": f'{request.form["mm"]}/{request.form["dd"]} {request.form["time"]}',
                "updated_at": datetime.datetime.utcnow(),
            }}
        )
        return redirect("/dashboard")

    doc = events_coll.find_one({"_id": oid})
    if not doc:
        return "Event not found", 404

    event = mongo_event_to_view(doc)
    return render_template("poster_edit.html", event=event)

if __name__ == "__main__":
    app.run(debug=True)