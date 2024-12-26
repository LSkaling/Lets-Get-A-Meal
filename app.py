from flask import Flask, render_template, url_for, Response, session, redirect, request, send_file
from datetime import datetime, timedelta
from googleapiclient.discovery import build
from google.oauth2 import service_account
import os.path
import google.auth.transport.requests
import pickle
import os
from dotenv import load_dotenv
import pytz
import logging
from google.oauth2 import service_account
from saml import saml_bp
from flask_saml2.sp import ServiceProvider
from flask_saml2.idp.idp import IdentityProvider
from flask_saml2.utils import certificate_from_file

from authlib.integrations.flask_client import OAuth
from flask_session import Session
import redis



logging.getLogger('root').setLevel(logging.ERROR)

load_dotenv()

SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'meals:'
app.config['SESSION_REDIS'] = redis.from_url('redis://localhost:6379')


Session(app)

# OIDC Configuration (replace with your IdP details)
app.config['OIDC_CLIENT_ID'] = os.getenv("CLIENT_ID")
app.config['OIDC_CLIENT_SECRET'] = os.getenv("CLIENT_SECRET")
app.config['OIDC_DISCOVERY_URL'] = 'https://idp.stanford.edu/.well-known/openid-configuration'

oauth = OAuth(app)

oidc = oauth.register(
    name='oidc',
    client_id=app.config['OIDC_CLIENT_ID'],
    client_secret=app.config['OIDC_CLIENT_SECRET'],
    server_metadata_url=app.config['OIDC_DISCOVERY_URL'],
    client_kwargs={
        'scope': 'openid',
    }
)





def authenticate():
    creds = service_account.Credentials.from_service_account_file(
        'service_account.json',
        scopes=['https://www.googleapis.com/auth/calendar.readonly']
    )
    return creds

def prepare_request(request):
    url_data = request.url.split(request.path)
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': url_data[0].replace('http://', '').replace('https://', ''),
        'server_port': request.environ['SERVER_PORT'],
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }



@app.route('/login')
def login():
    redirect_uri = url_for('auth', _external=True)
    return oidc.authorize_redirect(redirect_uri)

@app.route('/auth')
def auth():
    app.logger.info(f"Session at /auth: {session}")
    if 'state' not in session:
        return redirect('/login')    
    # Exchange authorization code for token
    token = oidc.authorize_access_token()
    user_info = oidc.parse_id_token(token)  # Decode user info from ID token
    session['user'] = user_info
    return redirect('/')  # Redirect to dashboard or protected page


@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return f"Hello, {session['user']['name']}!"
    return redirect('/login')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/')
def home():
    tz = pytz.timezone('America/Los_Angeles')

    cards = [
        {"title": "Card 1", "box1": {"large": "Busy", "small": "Lunch", "color": "#f0f0f0"}, "box2": {"large": "Busy", "small": "Dinner", "color": "#e6e6e6"}},
        {"title": "Card 2", "box1": {"large": "Busy", "small": "Lunch", "color": "#f0f0f0"}, "box2": {"large": "Busy", "small": "Dinner", "color": "#e6e6e6"}},
        {"title": "Card 3", "box1": {"large": "Busy", "small": "Lunch", "color": "#f0f0f0"}, "box2": {"large": "Busy", "small": "Dinner", "color": "#e6e6e6"}},
        {"title": "Card 4", "box1": {"large": "Busy", "small": "Lunch", "color": "#f0f0f0"}, "box2": {"large": "Busy", "small": "Dinner", "color": "#e6e6e6"}},
        {"title": "Card 5", "box1": {"large": "Busy", "small": "Lunch", "color": "#f0f0f0"}, "box2": {"large": "Busy", "small": "Dinner", "color": "#e6e6e6"}},
        {"title": "Card 6", "box1": {"large": "Busy", "small": "Lunch", "color": "#f0f0f0"}, "box2": {"large": "Busy", "small": "Dinner", "color": "#e6e6e6"}},
        {"title": "Card 7", "box1": {"large": "Busy", "small": "Lunch", "color": "#f0f0f0"}, "box2": {"large": "Busy", "small": "Dinner", "color": "#e6e6e6"}},
    ]

    for index, card in enumerate(cards):
        today = datetime.now(tz)
        # convert to start of day
        today = today.replace(hour=0, minute=0, second=0, microsecond=0)
        days_until = index
        date_formatted = today + timedelta(days=days_until)
        card["title"] = date_formatted.strftime("%A, %b %d")

    creds = authenticate()
    service = build('calendar', 'v3', credentials=creds)

    # Get current date in tz and set to midnight
    now = datetime.now(tz).replace(hour=0, minute=0, second=0, microsecond=0)

    # Calculate next week's date at midnight
    next_week = now + timedelta(days=7)

    # Convert to ISO format with timezone info
    now_iso = now.isoformat()
    next_week_iso = next_week.isoformat()

    events_result = service.events().list(
        calendarId='f3197c716485707a3468b83c415a7200495fb284fc666d8f38753b8fd31c0652@group.calendar.google.com',
        timeMin=now_iso,
        timeMax=next_week_iso,
        singleEvents=True,
        orderBy='startTime'
    ).execute()

    events = events_result.get('items', [])

    for event in events:
        start = event['start'].get('dateTime', event['start'].get('date'))
        start = datetime.strptime(start, "%Y-%m-%dT%H:%M:%S%z")
        start = start.astimezone(tz)
        
        end = event['end'].get('dateTime', event['end'].get('date'))
        end = datetime.strptime(end, "%Y-%m-%dT%H:%M:%S%z")
        end = end.astimezone(tz)

        days_until = (start - now).days

        title = event['summary']
        if title.lower() == "lunch" or title.lower() == "brunch":
            cards[days_until]["box1"]["small"] = title
            cards[days_until]["box1"]["color"] = "#90EE90"
            cards[days_until]["box1"]["large"] = f"{start.strftime('%I:%M %p')}"# - {end.strftime('%I:%M %p')}"
        elif title.lower() == "dinner":
            cards[days_until]["box2"]["small"] = "Dinner"
            cards[days_until]["box2"]["color"] = "#90EE90"
            cards[days_until]["box2"]["large"] = f"{start.strftime('%I:%M %p')}"# - {end.strftime('%I:%M %p')}"


    if not events:
        print('No upcoming events found.')

    else:
        for event in events:
            start = event['start'].get('dateTime', event['start'].get('date'))
            print(f"{event['summary']} - {start}")


    return render_template('index.html', cards=cards)

if __name__ == '__main__':
    app.run(debug=True)

 
