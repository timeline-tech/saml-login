from saml2 import BINDING_HTTP_POST
from saml2.config import SPConfig

def get_saml_config():
    config = {
        'entityid': 'http://127.0.0.1:5000/saml/metadata',
        'metadata': {
            'remote': [
                {
                    'url': 'https://dev-11600264.okta.com/app/exkjctckcqWgvgzmO5d7/sso/saml/metadata'
                }
            ],
        },
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        ('http://127.0.0.1:5000/saml/acs', BINDING_HTTP_POST),
                    ],
                    'single_logout_service': [
                        ('https://login.microsoftonline.com/ab2372e6-09e5-475a-8660-37fac8a7ef28/saml2', BINDING_HTTP_POST),
                    ],
                },
                'allow_unsolicited': True,
                'key_file': 'private_key.pem',  # Path to your private key
                'cert_file': 'certificate.pem'   # Path to your self-signed certificate
            },
        },
    }
    sp_config = SPConfig()
    sp_config.load(config)
    return sp_config