# coding: utf-8
from . import main
from .. import db

from flask import request, render_template, redirect
from ..models import Users, GrantCodes, Clients, Tokens
from ..helpers import secure_jsonify as jsonify
from uuid import uuid4
from hashlib import sha256
import simplejson as json
import datetime

@main.route('/clients', methods=['GET', 'POST'])
def op_clients():
    if request.method == 'GET':
        clients = [c.to_dict() for c in db.session.query(Clients).all()]
        return jsonify({'clients': clients})
    elif request.method == 'POST':
        data = json.loads(request.data)
        name, type, redirect_uri = data["name"], data["type"], data["redirect_uri"]
        client = Clients.new(name, type, redirect_uri)
        db.session.add(client)
        db.session.commit()
        return jsonify({'client': client.to_dict(show_secret=True)})



def client_identifier():
    if request.method == 'GET':
        query = request.args

        response_type = query.get('response_type', None)
        client_id = query.get('client_id', None)
        redirect_uri = query.get('redirect_uri', None)
        scope = query.get('scope', None)
        state = query.get('state', '')

        query = {}
        client = Clients.fetch(client_id)

        if state:
            query['state'] = state

        error = False
        if  response_type != 'token' and response_type != 'code':
            query['error'] = 'unsupported_response_type'
            error = True
        elif not client or not client_id:
            query['error'] = 'invalid_request'
            error = True
        elif scope is None:
            """scopeがNoneの場合のエラー処理"""
            query['error'] = 'invalid_scope'
            error = True

        # elif client.redirect_uri != redirect_uri:
        #     # 不正なredirect_uriの場合はリダイレクトさせない。
        #     query['error'] = 'unauthorized_client'
        #     redirect_uri=''
        #     error = True

        if error:
            uri = []
            for k, v in query.items():
                uri.append("{k}={v}".format(k=k, v=v))
            if response_type == 'token':
                url = redirect_uri + "#" + "&".join(uri)
            elif response_type == 'code':
                url = redirect_uri + "?" + "&".join(uri)
            return redirect(url, code=302)

        hidden_value =  { "client_id" : client_id, "redirect_uri" : redirect_uri, "response_type" : response_type, "state": state, "scope" : scope}

        # ユーザ認証
        return render_template('approval_auth.html', hidden_value=hidden_value)

def req_auth():
    from datetime import datetime, timedelta
    user_id = request.form.get('user_id')
    password = request.form.get('password')
    client_id = request.form.get('client_id')
    redirect_uri = request.form.get('redirect_uri')
    state = request.form.get('state')
    scope = request.form.get('scope')
    response_type = request.form.get('response_type')

    error = False
    query = {}

    if state:
        query['state'] = state

    # client auth
    client = Clients.fetch(client_id)

    if not client or not client_id:
        query['error'] = 'invalid_request'
        error = True

    if redirect_uri != client.redirect_uri:
        if response_type == 'token':
            query['error'] = 'unauthorized_client'
            redirect_uri=''
            error = True
        elif redirect_uri is not None and response_type == 'code':
            query['error'] = 'unauthorized_client'
            redirect_uri=''
            error = True

    # user auth
    user = Users.fetch(user_id, password)
    if not user:
        query['error'] = 'access_denied'
        error = True

    if error:
        uri = []
        for k, v in query.items():
            uri.append("{k}={v}".format(k=k, v=v))

        if response_type == 'token':
            url = redirect_uri + "#" + "&".join(uri)
        elif response_type == 'code':
            url = redirect_uri + "?" + "&".join(uri)

        return redirect(url, code=302)

    elif response_type == 'token':
        # token 発行
        token = Tokens.new(user_id, client_id, scope)
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
        for k, v in response.items():
            uri.append("{k}={v}".format(k=k, v=v))
        url = redirect_uri + "#" + "&".join(uri)

        return redirect(url, code=302)

    elif response_type == 'code':
        grant_code = GrantCodes.new(user_id, client_id, redirect_uri, scope)
        db.session.add(grant_code)
        db.session.commit()
        if state is None:
            return redirect(client.redirect_uri+"?code="+grant_code.code)
        else:
            return redirect(client.redirect_uri+"?code="+grant_code.code+"&state="+state) 


@main.route('/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'GET':
        return client_identifier()
    elif request.method == 'POST':
        return req_auth()

@main.route('/token',methods=['POST'])
def req_access():
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")
    client_id = request.form.get("client_id")

    grant_code = GrantCodes.fetch_by_code(code)
    if grant_code is None:
        #return err msg
        return redirect(redirect_uri+"?error=invalid_request")

    if grant_code.client_id != client_id :
        #return err msg
        return redirect(redirect_uri+"?error=invalid_request")

    if grant_type != "authorization_code" or code is None or client_id is None:
        #return err msg
        return redirect(redirect_uri+"?error=invalid_request")

    if grant_code.redirect_uri is not None and (redirect_uri is None or redirect_uri != grant_code.redirect_uri):
        #return err msg
        return redirect(redirect_uri+"?error=invalid_request")

    token = Tokens.new(grant_code.user_id, client_id, grant_code._scopes,
            grant_code = code,
            is_refresh=True)
    db.session.add(token)
    db.session.commit()

    return jsonify(token.to_dict())
