from . import main
from .. import db
from ..models import Clients

from flask import request
from ..helpers import secure_jsonify as jsonify
import simplejson as json

import requests



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


def client_start():
    regist = op_clients()
    payload = {'response_type': 'token',
            'client_id': regist['name'],
            'redirect_uri': regist['redirect_uri']}
    requests.get("/client_identifier", params=payload)


@main.route('/client_identifier', methods=['GET'])
def client_identifier():
    if request.method == 'GET':
        query = request.args

        response_type = query['response_type']
        client_id = query['client_id']
        redirect_uri = query['redirect_uri']
        scope = query['scope']
        state = query['state']

        if not response_type == 'token':
            response = redirect_uri + "#error=invalid_request&state=" + state
            return redirect_uri(response, code=302)

        client = Clients.fetch(client_id, redirect_uri)
        if not client or client['redirect_uri'] != redirect_uri:
            response = "#error=invalid_request&state=" + state
            return redirect_uri(response, code=302)

        # ユーザ認証
        return render_template('form.html', client_id=client_id, state=state)

@main.route('/auth', method=['POST'])
def auth():
    from datetime import datetime, timedelta
    user_id = request.form['user_id']
    password = request.form['password']
    client_id = request.form['client_id']
    if not Users.fetch(user_id, password):

    scopes = Users.fetch(user_id, password)['scopes']

    # token 発行
    token = Tokens.new(client_id, user_id, scopes)
    db.session.add(token)
    db.session.commit()

    # 302 にredirect_uriを送る
    response = {}
    response['access_token'] = token['access_token']
    response['token_type'] = 'bearer'
    response['expires_in'] = token['access_token_expire_date'] - datetime.now()
    response['scope'] = token['scope']
    response['state'] = request.form['state']

    if not Clients.fetch(client_id):
        response = redirect_uri + "#error=invalid_request&state=" + response['state']
        return redirect_uri(response, code=302)

    redirect_uri = ['redirect_uri']
    uri = []
    for k, v in response:
        uri.append("{k}={v}".format(k=k, v=v))
    url = redirect_uri + "#" + "&".join(uri)

    return redirect(url, code=302)
