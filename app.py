from flask import Flask, render_template, request

app = Flask(__name__)

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

@app.route("/profile")
def profile():
    return "Profile page (TODO)"

@app.route("/dashboard")
def dashboard():
    return "Dashboard page (TODO)"

if __name__ == "__main__":
    app.run(debug=True)