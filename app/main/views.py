from . import main
from .. import db
from ..models import Clients

from flask import request
from ..helpers import secure_jsonify as jsonify
from uuid import uuid4
from hashlib import sha256
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


@main.route('/approval', method=['GET','POST'])
def op_approval():
    if request.method == 'GET':
        response_type = request.args['response_type']
        client_id = request.args['client_id']
        redirect_uri = request.args['redirect_uri']
        scope = request.args['scope']
        state = request.args['state']

        client = Clients.fetch(client_id)

        if response_type != "" and client_id != "":
            """resorce-server approval"""
            code = sha256(uuid4().hex).hexdigest()
            if state == "":
                return redirect(client.redirect_uri+"?code="+code)
            else :
                return redirect(client.redirect_uri+"?code="+code+"&state="+state) 
        else :
            """invalid_request"""
            if state == "":
                return redirect(client.redirect_uri+"?error=invalid_request")
            else :
                return redirect(client.redirect_uri+"?error=invalid_request&state="+state)

