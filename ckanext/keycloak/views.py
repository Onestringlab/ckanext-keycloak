import logging
import ckan.model as model
import ckan.lib.helpers as h
import ckan.plugins as plugins
import ckanext.keycloak.helpers as helpers

from os import environ
from ckan.logic import get_action
from ckan.plugins import toolkit as tk
from ckan.common import g, session, config
from ckanext.keycloak.keycloak import KeycloakClient
from ckan.views.user import set_repoze_user, RequestResetView
from flask import Blueprint,jsonify,make_response,redirect,request

from ckanext.keycloak.utils import get_username, get_profile_by_username, validate_token

log = logging.getLogger(__name__)

keycloak = Blueprint('keycloak', __name__, url_prefix='/user')

server_url = tk.config.get('ckanext.keycloak.server_url', environ.get('CKANEXT__KEYCLOAK__SERVER_URL'))
client_id = tk.config.get('ckanext.keycloak.client_id', environ.get('CKANEXT__KEYCLOAK__CLIENT_ID'))
realm_name = tk.config.get('ckanext.keycloak.realm_name', environ.get('CKANEXT__KEYCLOAK__REALM_NAME'))
redirect_uri = tk.config.get('ckanext.keycloak.redirect_uri', environ.get('CKANEXT__KEYCLOAK__REDIRECT_URI'))
client_secret_key = tk.config.get('ckanext.keycloak.client_secret_key', environ.get('CKANEXT__KEYCLOAK__CLIENT_SECRET_KEY'))
logout_uri = tk.config.get('ckanext.keycloak.logout_uri', environ.get('CKANEXT__KEYCLOAK__LOGOUT_URI'))
ckan_url = tk.config.get('ckanext.keycloak.ckan_url', environ.get('CKANEXT__KEYCLOAK__CKAN_URL'))
api_url = tk.config.get('ckanext.keycloak.api_url', environ.get('CKANEXT__KEYCLOAK__API_URL'))
fe_url = tk.config.get('ckanext.keycloak.fe_url', environ.get('CKANEXT__KEYCLOAK__FE_URL'))

client = KeycloakClient(server_url, client_id, realm_name, client_secret_key)

def _log_user_into_ckan(resp):
    """ Log the user into different CKAN versions.
    CKAN 2.10 introduces flask-login and login_user method.
    CKAN 2.9.6 added a security change and identifies the user
    with the internal id plus a serial autoincrement (currently static).
    CKAN <= 2.9.5 identifies the user only using the internal id.
    """
    if tk.check_ckan_version(min_version="2.10"):
        from ckan.common import login_user
        login_user(g.user_obj)
        return

    if tk.check_ckan_version(min_version="2.9.6"):
        user_id = "{},1".format(g.user_obj.id)
        log.info(f'user_id 2.9.6:{user_id}')
    else:
        user_id = g.user
        log.info(f'user_id else:{user_id}')
    set_repoze_user(user_id, resp)

    log.info(u'User {0}<{1}> logged in successfully'.format(g.user_obj.name, g.user_obj.email))

def sso():
    # log.info("SSO Login")
    # auth_url = None
    # try:
    #     log.info(f"{client.get_auth_url(redirect_uri=redirect_uri)}")
    #     auth_url = client.get_auth_url(redirect_uri=redirect_uri)
    # except Exception as e:
    #     log.error("Error getting auth url: {}".format(e))
    #     return tk.abort(500, "Error getting auth url: {}".format(e))
    # return tk.redirect_to(auth_url)

    try:
        auth_url = server_url
        auth_url = (f"{auth_url}?redirect_uri={redirect_uri}&application=ckan")
        log.info(f"{auth_url}")
    except Exception as e:
        log.error("Error getting auth url: {}".format(e))
        return tk.abort(500, "Error getting auth url: {}".format(e))
    return tk.redirect_to(auth_url)

def sso_login():
    try:
        data = tk.request.args
        # log.info(f"Data: {data}")
        token = client.get_token(data['code'], redirect_uri)
        # log.info(f"Token: {token}")
        userinfo = client.get_user_info(token)
        email = userinfo['email']
        fullname = email.replace('@', ' ')
        # log.info("SSO Login: {}".format(userinfo))
        if userinfo:
            user_dict = {
                'name': helpers.ensure_unique_username_from_email(email),
                'email': email,
                'password': helpers.generate_password(),
                'fullname': fullname,
                'plugin_extras': ''
            }
            # log.info(user_dict)
            context = {"model": model, "session": model.Session}
            g.user_obj = helpers.process_user(user_dict)
            g.user = g.user_obj.name
            context['user'] = g.user
            context['auth_user_obj'] = g.user_obj

            response = tk.redirect_to(tk.url_for('user.me', context))

            _log_user_into_ckan(response)
            log.info("Logged in success")
            return response
        else:
            return tk.redirect_to(tk.url_for('user.login'))
    except Exception as e:
        log.error(e)
        return tk.redirect_to(tk.url_for('user.login'))

def sso_check_post():
    try:
        email = 'anonymous@somedomain.com'
        fullname = email.replace('@', ' ')

        token = request.form.get('token')

        if token:
            if not token.startswith("Bearer "):
                return tk.redirect_to(fe_url)
            
            token_value = token.split(" ", 1)[1]
            validated = validate_token(api_url, token_value)
            if not validated:
                return tk.redirect_to(fe_url)

            _, email = get_username(token_value)
            username = email.split('@')[0]
            fullname = email.replace('@', ' ')

            if email:
                user_dict = {
                    'name': helpers.ensure_unique_username_from_email(email),
                    'email': email,
                    'password': helpers.generate_password(),
                    'fullname': fullname,
                    'plugin_extras': ''
                }
                context = {"model": model, "session": model.Session}
                g.user_obj = helpers.process_user(user_dict)
                g.user = g.user_obj.name
                context['user'] = g.user
                context['auth_user_obj'] = g.user_obj

                response = tk.redirect_to(tk.url_for('user.me', context))

                _log_user_into_ckan(response)
                log.info("Logged in success")
                return response
            else:
                return tk.redirect_to(fe_url)
    except Exception as e:
        log.error(e)
    return tk.redirect_to(fe_url)

def reset_password():
    email = tk.request.form.get('user', None)
    if '@' not in email:
        log.info(f'User requested reset link for invalid email: {email}')
        h.flash_error('Invalid email address!')
        return tk.redirect_to(tk.url_for('user.request_reset'))
    user = model.User.by_email(email)
    if not user:
        log.info(u'User requested reset link for unknown user : {}'.format(email))
        return tk.redirect_to(tk.url_for('user.login'))
    user_extras = user[0].plugin_extras
    log.info(f"user_extras: {user_extras}")
    if user_extras and user_extras.get('idp', None) == 'google':
        log.info(u'User requested reset link for google user: {}'.format(email))
        h.flash_error('Invalid email address')
        return tk.redirect_to(tk.url_for('user.login'))
    return RequestResetView().post()

def sso_logout():
    log.info("**************** Logout success 4 ********************")

    response = tk.redirect_to(f"{logout_uri}")
    response = make_response(response)

    domain_url = tk.config.get('ckanext.keycloak.domain_url', environ.get('CKANEXT__KEYCLOAK__DOMAIN_URL'))
    cookie_value = ''
    if domain_url == 'localhost:5000':
        cookie_value = request.cookies.get('auth_tkt')
        log.info(f'domain_url: {domain_url}')
        response.delete_cookie('auth_tkt', path='/')
    else:
        log.info(f'domain_url: {domain_url}')
        cookie_value = request.cookies.get('auth_tkt')
        response.delete_cookie('auth_tkt', path='/')
        response.delete_cookie('auth_tkt', path='/', domain=f'.{domain_url}')

    return response

def sso_user_delete():
    try:
        payload = request.get_json()
        username = payload.get('username','')
        userid = payload.get('userid','')

        if userid:
            user_id = userid
        if username:
            user_id = username

        email = "anonymous@somedomain.com"
        username = "anonymous"
        token = request.headers.get("Authorization")
        if token:
            if not token.startswith("Bearer "):
                return jsonify({"error": "Invalid authorization format"}), 400

            token_value = token.split(" ", 1)[1]
            _, email = get_username(token_value)
            username = email.split('@')[0]

            params = {'id': user_id}
            context = {'user':username, 'ignore_auth': True}
            response = get_action('user_delete')(context, params)

            return jsonify({"success": True, "email": email, "username": username + " was deleted"})
        else:
            return jsonify({"success": False, "email": email, "username": username})
    except Exception as e:
        return jsonify({"error": f"{str(e)}"}), 400

def sso_login_welcome():
    return jsonify({
                "message": "Welcome to SSO 10.2",
                "success": True
            })

def get_blueprint():
    return keycloak

keycloak.add_url_rule('/sso', view_func=sso)
keycloak.add_url_rule('/logout', view_func=sso_logout)
keycloak.add_url_rule('/reset_password', view_func=reset_password, methods=['POST','GET'])

keycloak.add_url_rule('/sso_login', view_func=sso_login)
keycloak.add_url_rule('/sso_logout', view_func=sso_logout)
keycloak.add_url_rule('/sso_login_welcome', view_func=sso_login_welcome)
keycloak.add_url_rule('/sso_check_post', view_func=sso_check_post, methods=['POST'])
keycloak.add_url_rule('/sso_user_delete', view_func=sso_user_delete, methods=['POST'])