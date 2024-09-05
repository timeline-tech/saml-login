from saml2 import BINDING_HTTP_POST
from saml2.config import SPConfig

def get_saml_config():
    config = {
        'entityid': '',
        'metadata': {
            'remote': [
                {
                    'url': ''
                }
            ],
        },
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        ('', BINDING_HTTP_POST),
                    ],
                    'single_logout_service': [
                        ('', BINDING_HTTP_POST),
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