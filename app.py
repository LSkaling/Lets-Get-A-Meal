from flask import Flask, render_template, url_for, Response, session, redirect
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
import base64
import zlib
from xml.etree import ElementTree as ET
from urllib.parse import quote


logging.getLogger('root').setLevel(logging.ERROR)

load_dotenv()

SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']

def create_authn_request(entity_id, acs_url):
    """
    Manually create a SAML AuthnRequest.
    """
    request = ET.Element('samlp:AuthnRequest', {
        'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        'ID': '_{}'.format(base64.urlsafe_b64encode(zlib.compress(entity_id.encode())).decode('utf-8')),
        'Version': '2.0',
        'IssueInstant': '2024-12-25T10:55:10Z',
        'Destination': 'https://login.stanford.edu/idp/profile/SAML2/Redirect/SSO',
        'AssertionConsumerServiceURL': acs_url
    })

    issuer = ET.SubElement(request, 'saml:Issuer')
    issuer.text = entity_id

    # Encode the XML request
    xml_str = ET.tostring(request, encoding='utf-8', method='xml')
    saml_request = base64.b64encode(zlib.compress(xml_str)).decode('utf-8')

    return quote(saml_request)

class StanfordSSO(ServiceProvider):
    def get_blueprint_name(self):
        return 'flask_saml2_sp'  # This should match the blueprint name in saml.py

    # Override to provide correct entity ID
    def get_sp_entity_id(self):
        return "https://meals.lawtonskaling.com/saml/"

    def get_sp_config(self):
        return {
            'certificate': self.certificate,
            'private_key': self.private_key,
            'entity_id': self.get_sp_entity_id(),
            'acs_url': url_for(self.blueprint_name + '.acs', _external=True),
            'sls_url': url_for(self.blueprint_name + '.sls', _external=True),
        }

    def __init__(self, certificate, private_key):
        super().__init__()
        self.certificate = certificate
        self.private_key = private_key

    def get_acs_url(self):
        return url_for('saml.acs', _external=True)    

    # Manually implement metadata generation
    def get_metadata(self):
        entity_id = self.get_sp_entity_id()
        acs_url = self.get_acs_url()
        cert = self.certificate.replace("\n", "")

        # Create SAML metadata manually
        metadata = f"""
        <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
            <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <KeyDescriptor use="signing">
                    <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                        <X509Data>
                            <X509Certificate>{cert}</X509Certificate>
                        </X509Data>
                    </KeyInfo>
                </KeyDescriptor>
                <AssertionConsumerService
                    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    Location="{acs_url}"
                    index="1"/>
            </SPSSODescriptor>
        </EntityDescriptor>
        """
        return metadata.strip()

class StanfordIdentityProvider(IdentityProvider):
    def __init__(self, *args, **kwargs):
        super().__init__()  # Call parent with no arguments
        
        # Store configuration and set entity_id
        self.config = kwargs.get('config', {})
        self.entity_id = self.config.get('entity_id', 'https://idp.stanford.edu/')
        self.sso_url = self.config.get('sso_url', 'https://login.stanford.edu/idp/profile/SAML2/Redirect/SSO')
    
    def is_user_logged_in(self) -> bool:
        return 'user' in session

    def login_required(self):
        if not self.is_user_logged_in():
            return redirect(url_for('login'))

    def get_current_user(self):
        return session.get('user')

    def logout(self):
        session.clear()

    def make_login_request_url(self, next_url=None):
        """Generate the SSO URL with a SAMLRequest."""
        saml_request = create_authn_request(
            entity_id=self.entity_id,
            acs_url=url_for('flask_saml2_sp.acs', _external=True),
        )
        params = {
            'SAMLRequest': saml_request
        }
        if next_url:
            params['RelayState'] = next_url
        
        query = '&'.join([f"{k}={v}" for k, v in params.items()])
        return f"{self.sso_url}?{query}"



def authenticate():
    creds = service_account.Credentials.from_service_account_file(
        'service_account.json',
        scopes=['https://www.googleapis.com/auth/calendar.readonly']
    )
    return creds
def key_from_file(filepath):
    with open(filepath, 'r') as f:
        return f.read()

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('flask_saml2_sp.login'))
        return f(*args, **kwargs)
    return decorated_function



app = Flask(__name__)

# Initialize StanfordSSO with certificate and key during instantiation
sp = StanfordSSO(
    certificate=certificate_from_file('cert.pem'),
    private_key=key_from_file('key.pem')
)

# Register the SAML blueprint
app.register_blueprint(sp.create_blueprint(), url_prefix='/saml')

# Store SAML SP in app config for reference if needed
app.config['SAML2_SP'] = sp

app.config['SAML2_IDENTITY_PROVIDERS'] = [
    {
        'CLASS': 'app.StanfordIdentityProvider',
        'OPTIONS': {
            'entity_id': 'https://idp.stanford.edu/',  # Stanford's IdP entity ID
            'sso_url': 'https://login.stanford.edu/idp/profile/SAML2/Redirect/SSO',
            'slo_url': 'https://login.stanford.edu/idp/profile/SAML2/Redirect/SLO',  # SLO if needed
            'certificate': certificate_from_file('idp_cert.pem')  # IdP public cert
        }
    }
]


# Service Provider Configuration
app.config['SAML2_SERVICE_PROVIDERS'] = [
    {
        'CLASS': 'flask_saml2.idp.idp.IdentityProvider',
        'OPTIONS': {
            'acs_url': 'https://meals.lawtonskaling.com/saml/acs/',
            'entity_id': 'https://meals.lawtonskaling.com/saml/',
        }
    }
]



@app.route('/')
@login_required
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

 
