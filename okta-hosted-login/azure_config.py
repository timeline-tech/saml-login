from saml2 import BINDING_HTTP_POST
from saml2.config import SPConfig

def get_saml_azure_config():
    config = {
        'entityid': 'http://127.0.0.1:5000',
        'metadata': {
            'remote': [
                {
                    'url': 'https://login.microsoftonline.com/ab2372e6-09e5-475a-8660-37fac8a7ef28/federationmetadata/2007-06/federationmetadata.xml?appid=cbf09074-3290-4d22-8336-318c6734b853'
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
                        ('https://login.microsoftonline.com/ab2372e6-09e5-475a-8660-37fac8a7ef28/federationmetadata/2007-06/federationmetadata.xml?appid=cbf09074-3290-4d22-8336-318c6734b853', BINDING_HTTP_POST),
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