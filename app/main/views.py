# coding: utf-8
from . import main
from .. import db
from ..responses import RedirectResponseBuilder, RedirectWithFlagmentResponseBuilder, BaseResponseBuilder
from six.moves.urllib.parse import urlparse

from flask import request, render_template, redirect, g
from ..models import Users, GrantCodes, Clients, Tokens
from ..helpers import secure_jsonify as jsonify
from uuid import uuid4
from hashlib import sha256
import simplejson as json
from datetime import datetime, timedelta


@main.route('/clients', methods=['GET', 'POST'])
def op_clients():
    if request.method == 'GET':
        clients = [c.to_dict() for c in db.session.query(Clients).all()]
        return jsonify({'clients': clients})
    elif request.method == 'POST':
        data = json.loads(request.data)
        name, type, redirect_uri = data["name"], data["type"], data[
            "redirect_uri"]

        if urlparse(redirect_uri).fragment != "":
            return jsonify({
                'error': 'The redirect_uri do not include flagment'
            })

        client = Clients.new(name, type, redirect_uri)
        db.session.add(client)
        db.session.commit()
        return jsonify({'client': client.to_dict(show_secret=True)})


@main.before_request
def before_request():
    if request.method == 'GET':
        data = request.args
    else:
        data = request.form

    response_type = data.get('response_type', None)
    grant_type = data.get('grant_type', None)
    if response_type == 'code':
        g.response_builder = RedirectResponseBuilder()

    elif response_type == 'token':
        g.response_builder = RedirectWithFlagmentResponseBuilder()

    elif grant_type == 'authorization_code':
        g.response_builder = RedirectResponseBuilder()

    elif grant_type in ["password", "client_credentials", "refresh_token"]:
        g.response_builder = BaseResponseBuilder()

    else:
        g.response_builder = BaseResponseBuilder()


@main.route('/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'GET':
        data = request.args
    else:
        data = request.form

    user_id = data.get('user_id', None)
    password = data.get('password', None)
    response_type = data.get('response_type', None)
    client_id = data.get('client_id', None)
    redirect_uri = data.get('redirect_uri', None)
    scope = data.get('scope', None)
    state = data.get('state', None)
    cancel = data.get('cancel', None)

    if state is not None:
        g.response_builder.set_state(state)

    if cancel == 'Cancel':
        return g.response_builder.make_error_response("access_denied")

    client = Clients.fetch(client_id)

    if client_id is None or client is None:
        return g.response_builder.make_error_response("invalid_request")

    g.response_builder.set_redirect_uri(client.redirect_uri)

    if response_type not in ['token', 'code']:
        return g.response_builder.make_error_response(
            "unsupported_response_type")

    if response_type == "token" and client.redirect_uri != redirect_uri:
        return g.response_builder.make_error_response("unauthorized_client")

    if response_type == "code" and redirect_uri is not None:
        g.response_builder.set_redirect_uri(redirect_uri)

    if scope is None:
        return g.response_builder.make_error_response("invalid_scope")

    # TODO: clientの持っている最大のスコープよりも指定されたスコープの方が必ず小さいかチェックする

    if request.method == 'GET':
        # ユーザ認証
        hidden_value = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "state": state,
            "scope": scope
        }
        return render_template('approval_auth.html', hidden_value=hidden_value)

    # user auth
    user = Users.fetch(user_id, password)
    if user is None:
        return g.response_builder.make_error_response("access_denied")

    if response_type == 'token':
        # token 発行
        token = Tokens.new(user_id, client_id, scope)
        db.session.add(token)
        db.session.commit()

        return g.response_builder.make_response(token.to_dict())

    elif response_type == 'code':
        grant_code = GrantCodes.new(user_id, client_id, redirect_uri, scope)
        db.session.add(grant_code)
        db.session.commit()
        response = {"code": grant_code.code}
        return g.response_builder.make_response(response)


@main.route('/token', methods=['POST'])
def req_access():
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")
    refresh_token = request.form.get("refresh_token")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    username = request.form.get("username")
    password = request.form.get("password")

    if grant_type not in ["authorization_code", "password", "client_credentials", "refresh_token"]:
        return g.response_builder.make_error_response("invalid_request")

    if grant_type == "authorization_code":
        grant_code = GrantCodes.fetch_by_code(code)

        if grant_code is None:
            return g.response_builder.make_error_response("invalid_request")

        if grant_code.client_id != client_id:
            return g.response_builder.make_error_response("invalid_request")

        if grant_code.redirect_uri is not None and (
            redirect_uri is None or redirect_uri != grant_code.redirect_uri):
            return g.response_builder.make_error_response("invalid_request")

        grant_code.lasped()
        db.session.add(grant_code)

        token = Tokens.new(
        grant_code.user_id,
        client_id,
        grant_code._scopes,
        grant_code=code,
        is_refresh=True)

    elif grant_type == "password":
        user = Users.fetch(username, password)
        client = Clients.authorize(client_id, client_secret)

        if user is None or client is None:
            return g.response_builder.make_error_response("access_denied")


        token = Tokens.new(username, client_id, client._scopes, is_refresh=True)

    elif grant_type == "client_credentials":
        client = Clients.authorize(client_id, client_secret)

        if client is None:
            return g.response_builder.make_error_response("access_denied")

        token = Tokens.new(None, client_id, client._scopes, is_refresh=False)

    elif grant_type == "refresh_token":
        old_token = Tokens.fetch_by_refresh_token(refresh_token)

        if old_token is None:
            return g.response_builder.make_error_response("invalid_request")

        token = old_token.create_token(scopes)
        db.session.delete(old_token)



    db.session.add(token)
    db.session.commit()

    return jsonify({'token': token.to_dict()})
