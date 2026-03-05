# Web Application Exercise

A little exercise to build a web application following an agile development process. See the [instructions](instructions.md) for more detail.

## Product vision statement

A single place for the NYU community to post, discover, and RSVP to campus events—so nothing gets missed and every event finds its audience.

## User stories

[User Stories](https://github.com/swe-students-spring2026/software-engineering-spring-2026-2-web-app-web-app-exercise/actions)
## Steps necessary to run the software

1. Clone the repository

2. Install pipenv:
   pip3 install pipenv

3. Activate the virtual environment:
   python3 -m pipenv shell

4. Install dependencies:
   pip3 install -r requirements.txt

5. Create a .env file with these variables:
   MONGO_DBNAME=
   MONGO_HOST=
   MONGO_USERNAME=
   MONGO_PASSWORD=
   SECRET_KEY=
   MONGO_TLS_SKIP_VERIFY=true

6. Run the app:
   python3 app.py

## Task boards

[Sprint 1](https://github.com/orgs/swe-students-spring2026/projects/23)
[Sprint 2](https://github.com/orgs/swe-students-spring2026/projects/58)