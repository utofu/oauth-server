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
            return 

        client = Clients.fetch(client_id)
        if not client:
            return 

        # ユーザ認証
        return render_template('form.html')

@main.route('/redirect_with_token', method=['GET'])
def redirect_with_token():
    # token 発行
    token = Tokens.new(client_id)

    token_type = 'bearer'
    expires_in = 





    # 302 にredirect_uriを送る
    expires_in
    scope
    state = 

    return redirect(, code=302)


