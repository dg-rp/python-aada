import os
import base64
import uuid
import zlib
import getpass
import json
import boto3
import asyncio
import time
import pytz
import requests

from time import sleep
from datetime import datetime
from dateutil import tz
from xml.etree import ElementTree as ET
from urllib.parse import quote, parse_qs

from awscli.customizations.configure.writer import ConfigFileWriter
from pyppeteer.errors import BrowserError, TimeoutError, NetworkError

from . import KEYRING, LOGIN_URL, MFA_WAIT_METHODS
from .launcher import launch

if KEYRING:
    import keyring

class color:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARN = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    AQUA = '\033[96m'
    UNDERLINE = '\033[4m'


class MfaException(Exception):
    pass


class FormError(Exception):
    pass


class Login:
    _SAML_REQUEST = \
        '<samlp:AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xml' \
        'ns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id_{id}" Version' \
        '="2.0" IsPassive="false" IssueInstant="{date}" AssertionConsumerServ' \
        'iceURL="https://signin.aws.amazon.com/saml"><Issuer xmlns="urn:oasis' \
        ':names:tc:SAML:2.0:assertion">{app_id}</Issuer><samlp:NameIDPolicy F' \
        'ormat="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/></sa' \
        'mlp:AuthnRequest>'

    _BEGIN_AUTH_URL = '{url}/common/SAS/BeginAuth'
    _END_AUTH_URL = '{url}/common/SAS/EndAuth'
    _PROCESS_AUTH_URL = '{url}/common/SAS/ProcessAuth'
    _SAML_URL = '{url}/{tenant_id}/saml2?SAMLRequest={saml_request}'
    _REFERER = '{url}/{tenant_id}/login'

    _CREDENTIALS = ['aws_access_key_id', 'aws_secret_access_key',
                    'aws_session_token']
    _MFA_DELAY = 3
    _MFA_TIMEOUT = 60  # timeout in seconds to process MFA
    _AWAIT_TIMEOUT = 30000
    _SLEEP_TIMEOUT = 500
    _EXEC_PATH = os.environ.get('CHROME_EXECUTABLE_PATH')
    _RETRIES = 5

    def __init__(self, session, role=None, account=None, debug=False,
                 headless=True, saml_request=None):
        self._session = session
        self._role = role
        self._account = account
        self._debug = debug
        self._headless = headless
        self._config = self._session.get_scoped_config()
        self._config_writer = ConfigFileWriter()
        self._azure_tenant_id = self._config.get('azure_tenant_id')
        self._azure_app_id_uri = self._config.get('azure_app_id_uri')
        self._azure_mfa = self._config.get('azure_mfa')
        self._azure_kmsi = self._config.get('azure_kmsi', False)
        self._azure_username = self._config.get('azure_username')
        self._azure_password = None
        self._session_duration = int(self._config.get('session_duration', 3600))
        self._use_keyring = self._config.get('use_keyring')
        self.saml_response = None

        if saml_request:
            self._SAML_REQUEST = saml_request

    def __call__(self):
        return self._login()

    def _set_config_value(self, key, value):
        section = 'default'

        if self._session.profile is not None:
            section = 'profile {}'.format(self._session.profile)

        config_filename = os.path.expanduser(
            self._session.get_config_variable('config_file'))
        updated_config = {'__section__': section, key: value}

        if key in self._CREDENTIALS:
            config_filename = os.path.expanduser(
                self._session.get_config_variable('credentials_file'))
            section_name = updated_config['__section__']

            if section_name.startswith('profile '):
                updated_config['__section__'] = section_name[8:]
        self._config_writer.update_config(updated_config, config_filename)

    def _build_saml_login_url(self):
        saml_request = base64.b64encode(zlib.compress(
            self._SAML_REQUEST.strip().format(
                date=datetime.now().strftime("%Y-%m-%dT%H:%m:%SZ"),
                tenant_id=self._azure_tenant_id, id=uuid.uuid4(),
                app_id=self._azure_app_id_uri).encode('ascii'))[2:-4]).decode()
        return self._SAML_URL.format(
            url=LOGIN_URL, tenant_id=self._azure_tenant_id,
            saml_request=quote(saml_request))

    @classmethod
    async def _querySelector(cls, page, element, retries=0):
        if retries > cls._RETRIES:
            raise TimeoutError
        try:
            return await page.querySelector(element)
        except NetworkError:
            await page.waitFor(cls._SLEEP_TIMEOUT)
            return await cls._querySelector(page, element, retries + 1)

    async def _render_js_form(self, url, username, password, mfa=None):
        browser = await launch(executablePath=self._EXEC_PATH,
                               headless=self._headless)

        pages = await browser.pages()
        page = pages[0]

        async def _saml_response(req):
            if req.url == 'https://signin.aws.amazon.com/saml':
                self.saml_response = parse_qs(req.postData)['SAMLResponse'][0]
                await req.respond({
                    'status': 200, 'contentType': 'text/plain', 'body': ''
                })
            else:
                await req.continue_()

        await page.goto(url, waitUntil='domcontentloaded')
        await page.waitForSelector('input[name="loginfmt"]:not(.moveOffScreen)', {
            "visible": True
        })
        await page.focus('input[name="loginfmt"]')
        await page.keyboard.type(username)
        await page.authenticate({'username': username, 'password': password});
        await page.click('input[type=submit]')

        # response from myrealpageportal.com as a reference to know if we are on the VPN or not.
        response = requests.get('http://myrealpageportal.com/')

        if response.headers['Server'] == 'BigIP':
            print(f'Sending MFA prompt...')
            try:
                await page.waitForSelector('input[type="password"]:not(.moveOffScreen)', {
                    "visible": True
                })
                await page.focus('input[type="password"]')
                await page.keyboard.type(password)
                await page.click('span[id=submitButton]')
            except Exception as e:
                print(f'could not input/submit password:\n\n Error: {e}')
                pass

            try:
                await page.waitForSelector('input[type="submit"]:not(.moveOffScreen)', {
                    "visible": True
                })
                await page.click('input[type="submit"]')
                #print('hit submit on "stay signed in"')
            except Exception as e:
                print(f'Could not submit yes to stay signed in:\n\n Error: {e}')
                pass

            print('Waiting for SAML Response...')
            sleep(30)
            #await page.waitForNavigation({ "waitUntil": "load" })
            try:
                page.on('request', _saml_response)
                await page.setRequestInterception(True)
            except Exception as e:
                print(f'Could not get SAML response:\n\n Error: {e}')
        else:
            print('VPN connection validated...')
            # Wait for the page to load and then grab the saml response
            await page.waitForNavigation({ "waitUntil": "load" })
            try:
                await page.waitForSelector('input[type="password"]:not(.moveOffScreen)', {
                    "visible": True
                })
                await page.focus('input[type="password"]')
                await page.keyboard.type(password)
                await page.click('span[id=submitButton]')
            except Exception as e:
                print(f'could not input/submit password:\n\n Error: {e}')
                pass

            try:
                await page.waitForSelector('input[type="submit"]:not(.moveOffScreen)', {
                    "visible": True
                })
                await page.click('input[type="submit"]')
                #print('hit submit on "stay signed in"')
            except Exception as e:
                print(f'Could not submit yes to stay signed in:\n\n Error: {e}')
                pass

            page.on('request', _saml_response)
            await page.setRequestInterception(True)


        try:
            if await self._querySelector(page, '.has-error'):
                raise FormError

            if mfa:
                if self._azure_mfa not in MFA_WAIT_METHODS:
                    await page.waitForSelector('input[name="otc"]:not(.moveOffScreen)', {
                        "visible": True
                    })
                    await page.focus('input[name="otc"]')
                    mfa_token = input('Azure MFA Token: ')
                    for l in mfa_token:
                        await page.keyboard.sendCharacter(l)
                    await page.click('input[type=submit]')
                else:
                    print('Processing SAML response...')

            if self._azure_kmsi:
                await page.waitForSelector(
                    'form[action="/kmsi"]', timeout=self._AWAIT_TIMEOUT)
                await page.waitForSelector('#idBtn_Back')
                await page.click('#idBtn_Back')

            if not self.saml_response:
                page.on('request', _saml_response)
                await page.setRequestInterception(True)

            wait_time = time.time() + self._MFA_TIMEOUT
            while time.time() < wait_time and not self.saml_response:
                if await self._querySelector(page, '.has-error'):
                    raise FormError

            if not self.saml_response:
                raise TimeoutError

        except (TimeoutError, BrowserError, FormError) as e:
            print('An error occurred while authenticating, check credentials.')
            print(e)
            if self._debug:
                debugfile = 'aadaerror-{}.png'.format(
                    datetime.now().strftime("%Y-%m-%dT%H%m%SZ"))
                await page.screenshot({'path': debugfile})
                print('See screenshot {} for clues.'.format(debugfile))
            exit(1)

        finally:
            await browser.close()

    @staticmethod
    def _get_aws_roles(saml_response):
        aws_roles = []
        for attribute in ET.fromstring(base64.b64decode(saml_response)).iter(
                '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            if (attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
                for value in attribute.iter(
                        '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                    aws_roles.append(value.text)

        for role in aws_roles:
            chunks = role.split(',')
            if 'saml-provider' in chunks[0]:
                new_role = chunks[1] + ',' + chunks[0]
                index = aws_roles.index(role)
                aws_roles.insert(index, new_role)
                aws_roles.remove(role)
        return aws_roles

    def _assume_role(self, role_arn, principal_arn, saml_response):
        return boto3.client('sts').assume_role_with_saml(
            RoleArn=role_arn, PrincipalArn=principal_arn,
            SAMLAssertion=saml_response, DurationSeconds=self._session_duration)

    def _save_credentials(self, credentials, role_arn):
        self._set_config_value('aws_role_arn', role_arn)
        self._set_config_value('aws_access_key_id', credentials['AccessKeyId'])
        self._set_config_value('aws_secret_access_key', credentials[
            'SecretAccessKey'])
        self._set_config_value('aws_session_token', credentials['SessionToken'])

    @staticmethod
    def _choose_role(self, aws_roles):
        count_roles = len(aws_roles)
        if count_roles > 1:
            if self._role:
                return self._role, 'arn:aws:iam::592380362770:saml-provider/WAAD'
            else:
                allowed_values = list(range(1, count_roles + 1))
                for i, role in enumerate(aws_roles, start=1):
                    print('[ {} ]: {}'.format(i, role.split(',')[0]))

                print('Choose the role you would like to assume:')
                selected_role = int(input('Selection: '))
                while selected_role not in allowed_values:
                    print('Invalid role index, please try again')
                    selected_role = int(input('Selection: '))
                return aws_roles[selected_role - 1].split(',')[0], aws_roles[
                    selected_role - 1].split(',')[1]
        return aws_roles[0].split(',')[0], aws_roles[0].split(',')[1]

    @staticmethod
    def _post(session, url, data, headers):
        return json.loads(session.post(url, data=data, headers=headers).text)

    def _login(self):
        """

        :param parsed_args:
        :return:
        """
        url = self._build_saml_login_url()
        username_input = self._azure_username
        profile = self._session.profile if self._session.profile else 'default'
        role_stored_in_config = self._role
        kr_pass = None
        print(f'\n[{color.OKGREEN}Azure AD AWS CLI Authentication{color.END}]')
        print(f'{color.BOLD}Profile:{color.END} {color.AQUA}{profile}{color.END}')
        print(f'{color.BOLD}Role:{color.END} {color.AQUA}{role_stored_in_config}{color.END}')
        print(f'{color.BOLD}Username:{color.END} {color.AQUA}{self._azure_username}{color.END}')

        if KEYRING and self._use_keyring:
            try:
                print('Getting password from keyring')
                kr_pass = keyring.get_password('aada', self._azure_username)
            except Exception as e:
                print('Failed getting password from Keyring {}'.format(e))

        if kr_pass is not None:
            password_input = kr_pass
        else:
            password_input = getpass.getpass(f'{color.BOLD}Password:{color.END} ')

        print('-------------------------------------------------------------')
        print('Logging in...')

        asyncio.get_event_loop().run_until_complete(self._render_js_form(
            url, username_input, password_input, self._azure_mfa))

        if not self.saml_response:
            print('Something went wrong! No roles found!')
            exit(1)
        aws_roles = self._get_aws_roles(self.saml_response)
        role_arn, principal = self._choose_role(self, aws_roles)

        role_name = role_arn.split('/')[-1]

        print(f'{color.OKGREEN}Assuming role:{color.END} {role_name}')
        sts_token = self._assume_role(role_arn, principal, self.saml_response)
        credentials = sts_token['Credentials']
        self._save_credentials(credentials, role_arn)

        credential_experation_date = credentials['Expiration'].replace(tzinfo=tz.gettz('UTC')).astimezone(tz.tzlocal())
        experiation_delta = credentials['Expiration'] - datetime.utcnow().replace(tzinfo=pytz.UTC)
        time_till_experiation_seconds = experiation_delta.total_seconds()
        time_till_experiation_hours = int(time_till_experiation_seconds/60/60) + 1
        print(f'{color.OKGREEN}Expiration:{color.END} {credential_experation_date:%Y-%m-%d %H:%M:%S} ( {time_till_experiation_hours} hours )')
        print('-------------------------------------------------------------\n')
        return 0
