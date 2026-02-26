from flask import Flask, render_template, request
from flask_login import LoginManager, UserMixin, current_user, login_user 

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role
@login_manager.user_loader
def load_user(user_id):
    return User(user_id, "Attendee", "Organizer")

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
def event_detail(event_id):
    event = next((e for e in EVENTS if e["id"] == event_id), None)
    if not event:
        return "Event not found", 404
    return render_template("event_details.html", event=event)
@app.route("/login-as-organizer")
def login_as_organizer():
    # Create our dummy user
    test_user = User(id="1", username="Ermuunn", role="Organizer")
    
    # Tell Flask-Login to remember this user
    login_user(test_user)
    
    return "You are now logged in as an Organizer! <a href='/profile'>Go to Profile</a>"

@app.route("/login-as-attendee")
def login_as_attendee():
    test_user = User(id="2", username="Student_Guest", role="Attendee")
    login_user(test_user)
    return "You are now logged in as an Attendee! <a href='/profile'>Go to Profile</a>"
@app.route("/profile")
def profile():
    if not current_user.is_authenticated:
        # If not, redirect them to home or show an error
        return "You must be logged in to view this page.", 403
    events_to_show = []
    if current_user == "Organizer":
        events_to_show = EVENTS
    else:
        events_to_show = EVENTS[:2]
    return render_template("profile.html", user=current_user, events=events_to_show)
@app.route("/dashboard")
def dashboard():
    return "Dashboard page (TODO)"

if __name__ == "__main__":
    app.run(debug=True)