import requests
import random
import string

from flask import Flask, render_template, redirect, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from saml2 import BINDING_HTTP_POST
from saml2.client import Saml2Client
from saml2.response import StatusError
from saml_config import get_saml_config
from azure_config import get_saml_azure_config

from helpers import is_access_token_valid, is_id_token_valid, config
from user import User, SAMLUser


app = Flask(__name__)
app.config.update({'SECRET_KEY': ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=32))})

login_manager = LoginManager()
login_manager.init_app(app)


APP_STATE = 'ApplicationState'
NONCE = 'SampleNonce'


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login/oidc")
def login():
    # get request params
    query_params = {'client_id': config["client_id"],
                    'redirect_uri': config["redirect_uri"],
                    'scope': "openid email profile",
                    'state': APP_STATE,
                    'nonce': NONCE,
                    'response_type': 'code',
                    'response_mode': 'query'}

    # build request_uri
    request_uri = "{base_url}?{query_params}".format(
        base_url=config["auth_uri"],
        query_params=requests.compat.urlencode(query_params)
    )

    return redirect(request_uri)


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)


@app.route("/oidc/callback")
def callback():
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    code = request.args.get("code")
    if not code:
        return "The code was not returned or is not accessible", 403
    query_params = {'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': request.base_url
                    }
    query_params = requests.compat.urlencode(query_params)
    exchange = requests.post(
        config["token_uri"],
        headers=headers,
        data=query_params,
        auth=(config["client_id"], config["client_secret"]),
    ).json()

    # Get tokens and validate
    if not exchange.get("token_type"):
        return "Unsupported token type. Should be 'Bearer'.", 403
    access_token = exchange["access_token"]
    id_token = exchange["id_token"]

    if not is_access_token_valid(access_token, config["issuer"]):
        return "Access token is invalid", 403

    if not is_id_token_valid(id_token, config["issuer"], config["client_id"], NONCE):
        return "ID token is invalid", 403

    # Authorization flow successful, get userinfo and login user
    userinfo_response = requests.get(config["userinfo_uri"],
                                     headers={'Authorization': f'Bearer {access_token}'}).json()

    unique_id = userinfo_response["sub"]
    user_email = userinfo_response["email"]
    user_name = userinfo_response["given_name"]

    user = User(
        id_=unique_id, name=user_name, email=user_email
    )

    if not User.get(unique_id):
        User.create(unique_id, user_name, user_email)

    login_user(user)

    return redirect(url_for("profile"))


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route('/login/saml')
def saml_login():
    client = Saml2Client(get_saml_config())
    _, info = client.prepare_for_authenticate()
    for key, value in info['headers']:
        if key == 'Location':
            return redirect(value)
    return 'Unable to redirect'

# commenting to test the AZure AD

@app.route('/saml/okta/acs', methods=['POST'])
def saml_okta_acs():
    client = Saml2Client(get_saml_config())
    try:
        import base64
        from xml.etree import ElementTree as ET

        saml_response = request.form['SAMLResponse']
        decoded_response = base64.b64decode(saml_response)
        root = ET.fromstring(decoded_response)
        ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
        attributes = {}
        for attribute in root.findall('.//saml:Attribute', ns):
            # print(attribute)
            name = attribute.get('Name')
            values = [value.text for value in attribute.findall('saml:AttributeValue', ns)]
            attributes[name] = values
        user = SAMLUser(
        id_='unique_id', name=attributes['username'][0], email=attributes['email'][0]
            )

        # if not User.get(unique_id):
        User.create('unique_id', attributes['username'][0], attributes['email'][0])
        login_user(user)

        return redirect(url_for("profile"))
        # return 'Successfully logged in'
    except StatusError as e:
        return f"Login failed: {e}"

@app.route('/login/azure')
def saml_login_azure():
    client = Saml2Client(get_saml_azure_config())
    _, info = client.prepare_for_authenticate()
    for key, value in info['headers']:
        if key == 'Location':
            return redirect(value)
    return 'Unable to redirect'



@app.route('/saml/acs', methods=['GET', 'POST'])
def saml_azure_acs():
    client = Saml2Client(get_saml_azure_config())
    try:
        import base64
        from xml.etree import ElementTree as ET
        
        saml_response = request.form['SAMLResponse']
        decoded_response = base64.b64decode(saml_response)
        root = ET.fromstring(decoded_response)
        ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
        attributes = {}
        for attribute in root.findall('.//saml:Attribute', ns):
            # print(attribute)
            name = attribute.get('Name')
            values = [value.text for value in attribute.findall('saml:AttributeValue', ns)]
            attributes[name] = values
        username = attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname']
        email = attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']
        user = SAMLUser(
        id_='unique_id', name=username[0], email=email[0]
            )

        # if not User.get(unique_id):
        User.create('unique_id', username[0], email[0])
        login_user(user)
        return redirect(url_for("profile"))
        # return 'Successfully logged in'
    except StatusError as e:
        return f"Login failed: {e}"


if __name__ == '__main__':
    app.run(port=5000, debug=True)
