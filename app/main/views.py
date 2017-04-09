from . import main
from .. import db
from ..models import Clients

from flask import request, redirect
from ..helpers import secure_jsonify as jsonify
from uuid import uuid4
from hashlib import sha256
import simplejson as json
import datetime



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


@main.route('/approval', methods`=['GET','POST'])
def op_approval():
    if request.method == 'GET':
        response_type = request.get('response_type', None)
        client_id = request.get('client_id', None)
        redirect_uri = request.get('redirect_uri', None)
        scope = request.get('scope', None)
        state = request.get('state', None)
        if redirect_uri is None:
            redirect_uri = None
        if state is None:
            state = None

        """resorce-server approval"""
        client = Clients.fetch(client_id)

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

@app.route('/req_auth', methods=['POST'])
def req_auth():
    id=request.form["user_id"]
    password=request.form["password"]
    response_type=request.form["response_type"]
    client_id=request,form["client_id"]
    redirect_uri=request.form["redirect_uri"]
    scope=request.form["scope"]
    state=request.form["state"]

    """resorce-server approval"""
    client = Clients.fetch(client_id)

    if(Users.fetch(id,password) is None):
        return redirect(client.redirect_uri+"?error=access_denied")

    code = sha256(uuid4().hex).hexdigest()

    """現在の時間を取得し、30分の時間を加算することで制限時間を生成。"""
    expire_date = datetime.datetime.now() + datetime.timedelta(minutes=30)
            
    grant_code = GrantCodes.new(code,expire_date,scope,user_id,client_id,redirect_uri)
    db.session.add(grant_code)
    db.session.commit()
            
    if state is None:
        return redirect(client.redirect_uri+"?code="+code)
    else :
        return redirect(client.redirect_uri+"?code="+code+"&state="+state) 

@app.route('/req_access',methods=['POST'])
def req_access():
    grant_type = request.form["grant_type"]
    code = request.form["code"]
    redirect_uri = request.form["redirect_uri"]
    client_id = request.form["client_id"]

    grant_code = GrantCodes.fetch_by_code(code)
    

