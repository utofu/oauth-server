# coding: utf-8
from . import main
from .. import db
from ..models import Clients, Users, Tokens

from flask import request, render_template, redirect
from ..helpers import secure_jsonify as jsonify
import simplejson as json

@main.route('/clients', methods=['GET', 'POST'])
def op_clients():
    if request.method == 'GET':
        clients = [c.to_dict() for c in Clients.query.all()]
        return jsonify({'clients': clients})
    elif request.method == 'POST':
        data = json.loads(request.data)
        name, type, redirect_uri = data["name"], data["type"], data["redirect_uri"]
        client = Clients.new(name, type, redirect_uri)
        db.session.add(client)
        db.session.commit()
        return jsonify({'client': client.to_dict(show_secret=True)})


@main.route('/client_identifier', methods=['GET'])
def client_identifier():
    if request.method == 'GET':
        query = request.args

        response_type = query.get('response_type', None)
        client_id = query.get('client_id', None)
        redirect_uri = query.get('redirect_uri', None)
        scope = query.get('scope', None)
        state = query.get('state', '')

        query = []

        if state:
            query['state'] = state

        error = False
        if not response_type == 'token':
            query['error'] = 'unsupported_response_type'
            error = True

        client = Clients.fetch(client_id)
        elif not client or client.redirect_uri != redirect_uri:
            query['error'] = 'unauthorized_client'
            error = True

        if error:
            for k, v in query:
                uri.append("{k}={v}".format(k=k, v=v))
            url = redirect_uri + "#" + "&".join(uri)
            return redirect(url, code=302)

        # ユーザ認証
        return render_template('form.html', client_id=client_id, state=state)

@main.route('/auth', methods=['POST'])
def auth():
    from datetime import datetime, timedelta
    user_id = request.form.get('user_id')
    password = request.form.get('password')
    client_id = request.form.get('client_id')
    state = request.form.get('state')

    # client auth
    client = Clients.fetch(client_id)
    if not client:
        response = "#error=invalid_request&state=" + state
        return redirect(response, code=302)

    redirect_uri = client.redirect_uri

    # user auth
    user = Users.fetch(user_id, password)
    if not user:
        response = redirect_uri + "#error=invalid_request&state=" + state
        return redirect(response, code=302)

    scopes = user.scopes

    # token 発行
    token = Tokens.new(client_id, user_id, scopes)
    db.session.add(token)
    db.session.commit()

    # アクセストークンを付けてリダイレクト
    response = {}
    response['access_token'] = token.access_token
    response['token_type'] = 'bearer'
    response['expires_in'] = (token.access_token_expire_date - datetime.now()).total_seconds()
    response['scopes'] = token.scopes
    response['state'] = state

    uri = []
    for k, v in response:
        uri.append("{k}={v}".format(k=k, v=v))
    url = redirect_uri + "#" + "&".join(uri)

    return redirect(url, code=302)
