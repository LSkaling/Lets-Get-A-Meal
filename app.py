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

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from werkzeug.middleware.proxy_fix import ProxyFix
import json
from lxml import etree
import base64


logging.getLogger('root').setLevel(logging.ERROR)

load_dotenv()

SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']

app = Flask(__name__)
#app.secret_key = os.urandom(24)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)


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
    req = prepare_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.path.dirname(__file__), 'saml'))
    return redirect(auth.login())

# @app.route('/sso/acs', methods=['POST'])
# def acs():
#     print(request.headers)  # Log all headers
#     req = prepare_request(request)
#     auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.path.dirname(__file__), 'saml'))
#     auth.process_response()

#     errors = auth.get_errors()
#     print("SAML Response: ", auth.get_last_response_xml())  # Debugging
#     if errors:
#         print("Errors: ", errors)
#         return f"Error: {', '.join(errors)}"

#     session['user_data'] = auth.get_attributes()
#     return redirect('/')

def prepare_saml_auth():
    req = {
        'http_host': request.host,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }
    saml_path = os.path.join(os.path.dirname(__file__), 'saml')
    return OneLogin_Saml2_Auth(req, custom_base_path=saml_path)

@app.route('/sso/acs', methods=['POST'])
def acs():
    saml_response = request.form.get('SAMLResponse')
    with open('/tmp/saml_response.xml', 'wb') as f:
        f.write(base64.b64decode(saml_response))
    auth = prepare_saml_auth()
    auth.process_response()
    return redirect('/')



@app.route('/logout')
def logout():
    req = prepare_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.path.dirname(__file__), 'saml'))
    return redirect(auth.logout())

@app.route('/saml/metadata')
def metadata():
    # Load settings.json
    settings_path = os.path.join(os.path.dirname(__file__), 'saml', 'settings.json')
    with open(settings_path, 'r') as f:
        settings = json.load(f)

    # Generate SAML Metadata XML
    metadata_xml = generate_saml_metadata(settings)

    # Return XML Response
    return Response(metadata_xml, content_type='application/xml')

def generate_saml_metadata(settings):
    # Create XML Root
    entity_descriptor = etree.Element(
        "EntityDescriptor",
        xmlns="urn:oasis:names:tc:SAML:2.0:metadata",
        entityID=settings["sp"]["entityId"]
    )

    # SPSSODescriptor (Service Provider SSO Descriptor)
    spsso_descriptor = etree.SubElement(
        entity_descriptor, "SPSSODescriptor",
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
    )

    # Signing KeyDescriptor
    add_key_descriptor(spsso_descriptor, settings["sp"]["certificate"], "signing")

    # Encryption KeyDescriptor (Optional, if present in settings)
    if "encryptionCertificate" in settings["sp"]:
        add_key_descriptor(spsso_descriptor, settings["sp"]["encryptionCertificate"], "encryption")

    # AssertionConsumerService
    etree.SubElement(
        spsso_descriptor, "AssertionConsumerService",
        Binding=settings["sp"]["assertionConsumerService"]["binding"],
        Location=settings["sp"]["assertionConsumerService"]["url"],
        index="1"
    )

    # SingleLogoutService (Optional)
    if "singleLogoutService" in settings:
        etree.SubElement(
            spsso_descriptor, "SingleLogoutService",
            Binding=settings["sp"]["singleLogoutService"]["binding"],
            Location=settings["sp"]["singleLogoutService"]["url"]
        )

    # Serialize XML
    return etree.tostring(entity_descriptor, pretty_print=True, xml_declaration=True, encoding="UTF-8")


def add_key_descriptor(parent, cert_path, use):
    # Read certificate from file
    with open(cert_path, 'r') as f:
        cert = f.read().replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace('\n', '')

    # KeyDescriptor Element
    key_descriptor = etree.SubElement(parent, "KeyDescriptor", use=use)
    key_info = etree.SubElement(key_descriptor, "KeyInfo", xmlns="http://www.w3.org/2000/09/xmldsig#")
    x509_data = etree.SubElement(key_info, "X509Data")
    x509_certificate = etree.SubElement(x509_data, "X509Certificate")

    # Insert certificate data
    x509_certificate.text = cert    



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

 
