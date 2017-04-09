# coding: utf-8
from . import main
from .. import db
from ..models import Users, GrantCodes, Clients, Tokens
from flask import request, redirect, render_template
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


@main.route('/approval', methods=['GET'])
def op_approval():
    if request.method == 'GET':
        response_type = request.args.get('response_type', None)
        client_id = request.args.get('client_id', None)
        redirect_uri = request.args.get('redirect_uri', None)
        scope = request.args.get('scope', None)
        state = request.args.get('state', None)


        """resorce-server approval"""
        client = Clients.fetch(client_id)
        if client is None and redirect_uri is None:
            return "?error=invalid_request"
        elif client is None :
            return redirect(redirect_uri+"?error=invalid_request")

        if response_type != "code" or client_id is None or scope is None:
            """invalid_request"""
            if state is None:
                return redirect(client.redirect_uri+"?error=invalid_request")
            else :
                return redirect(client.redirect_uri+"?error=invalid_request&state="+state) 
            """scopeがNoneの場合のエラー処理"""
            if scope is None:
                return redirect(client.redirect_uri+"?error=invalid_scope")


        #ここにredirectでhtmlを渡して、パスワード,ユーザーIDを取得してmodelのUserからpasswordとuseridを比較しておkなら次へ
        return render_template('approval_auth.html',response_type=response_type,client_id= client_id,redirect_uri=redirect_uri,scope=scope,state=state)

@main.route('/req_auth', methods=['POST'])
def req_auth():
    id=request.form.get("user_id")
    password=request.form.get("password")
    response_type=request.form.get("response_type")
    client_id=request.form.get("client_id")
    redirect_uri=request.form.get("redirect_uri")
    scope=request.form.get("scope")
    state=request.form.get("state")


    """resorce-server approval"""
    client = Clients.fetch(client_id)
    if client is None:
        return redirect(client.redirect_uri+"?error=invalid_request")


    if not Users.fetch(id, password):
        return redirect(client.redirect_uri+"?error=access_denied")
   
            
    grant_code = GrantCodes.new(scope,id,client_id,redirect_uri)
    db.session.add(grant_code)
    db.session.commit()
            
    if state is None:
        return redirect(client.redirect_uri+"?code="+grant_code.code)
    else :
        return redirect(client.redirect_uri+"?code="+grant_code.code+"&state="+state) 

@main.route('/req_access',methods=['POST'])
def req_access():
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")
    client_id = request.form.get("client_id")

    grant_code = GrantCodes.fetch_by_code(code)
    if grant_code is None:
        #return err msg
        return redirect(redirect_uri+"?error=invalid_request1")

    if grant_code.client_id != client_id :
        #return err msg
        return redirect(redirect_uri+"?error=invalid_request2")

    if grant_code.redirect_uri is None :
        if grant_type != "authorization_code" or code is None or client_id is None:
            #return err msg
            return redirect(redirect_uri+"?error=invalid_request3")
    else :
        if grant_type != "authorization_code" or code is None or client_id is None or redirect_uri is None:
            #return err msg
            return redirect(redirect_uri+"?error=invalid_request4")
        else :
            if grant_code.redirect_uri is not None:    
                if redirect_uri != grant_code.redirect_uri:
                    print redirect_uri, "+" , type(grant_code.redirect_uri)
                    return redirect(redirect_uri+"?error=invalid_request5")



    token = Tokens.new(grant_code._scopes,grant_code.user_id,client_id,code)
    db.session.add(token)
    db.session.commit()

    if False :
        #err msg
        pass
    else :
        return jsonify(token.to_dict())




