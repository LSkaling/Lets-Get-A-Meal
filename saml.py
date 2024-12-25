from flask import Blueprint, current_app as app, Response
from flask_saml2.utils import certificate_from_file

saml_bp = Blueprint('saml_acs', __name__)

def key_from_file(filepath):
    """Custom method to load private key from file."""
    with open(filepath, 'r') as f:
        return f.read()

@saml_bp.route('/metadata')
def metadata():
    sp = app.config['SAML2_SP']
    
    # Set SP certificate and key manually
    sp.certificate = certificate_from_file('cert.pem')
    sp.private_key = key_from_file('key.pem')
    
    metadata = sp.get_metadata()
    print(metadata)
    return Response(metadata, content_type='application/xml')

@saml_bp.route('/login')
def login():
    sp = app.config['SAML2_SP']
    return sp.login_redirect()

@saml_bp.route('/acs', methods=['POST'])
def acs():
    sp = app.config['SAML2_SP']
    auth_response = sp.parse_authn_request_response(request.form['SAMLResponse'], binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')

    if auth_response.is_success():
        session['user'] = auth_response.name_id
        return redirect(url_for('dashboard'))
    else:
        return "Authentication Failed", 403    