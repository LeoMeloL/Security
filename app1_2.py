# app1.2.py

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import jwt
from datetime import datetime, timedelta
from sqlalchemy import text 
from logging.handlers import RotatingFileHandler
import pickle
import base64
import os 
import time
import logging
from waf import waf_protection
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# --- 1. CONFIGURAÇÃO INICIAL ---
app = Flask(__name__)
limiter = Limiter(key_func=get_remote_address, app=app)

waf_protection(app)

handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1) 
handler.setLevel(logging.INFO)
formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] IP:%(remote_addr)s - %(message)s'
)
handler.setFormatter(formatter)

class RequestFormatter(logging.Formatter):
    def format(self, record):
        if 'remote_addr' not in record.__dict__:
            record.remote_addr = 'N/A' 
        return super().format(record)

request_formatter = RequestFormatter(
    '%(asctime)s [%(levelname)s] IP:%(remote_addr)s - %(message)s'
)
handler.setFormatter(request_formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

@app.before_request
def log_request_info():
    app.logger.info(
        f"{request.method} {request.path} data={request.get_data(as_text=True)}",
        extra={'remote_addr': request.remote_addr}
    )

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'minha-chave-super-secreta'

db = SQLAlchemy(app)

# --- 2. MODELOS DO BANCO DE DADOS (Tabelas) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    # NOVA COLUNA PARA O SALDO DO USUÁRIO
    balance = db.Column(db.Float, nullable=False, default=0.0)

# NOVA TABELA PARA OS VALE-PRESENTES
class GiftCard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(80), unique=True, nullable=False)
    value = db.Column(db.Float, nullable=False)
    is_used = db.Column(db.Boolean, default=False, nullable=False)    

@app.route('/me', methods=['GET'])
@limiter.limit("5 per minute")
def get_me():
    user = User.query.get(1)
    if not user:
        return jsonify({"message": "Usuário não encontrado"}), 404
    return jsonify({"username": user.username, "balance": user.balance})

@app.route('/giftcard/redeem', methods=['POST'])
@limiter.limit("5 per minute")
def redeem_gift_card():
    user_id = 1 
    data = request.get_json()
    card_code = data.get('code')

    card = GiftCard.query.filter_by(code=card_code).first()

    if not card:
        return jsonify({"message": "Vale-presente não encontrado"}), 404

    if card.is_used:
        return jsonify({"message": "Este vale-presente já foi resgatado"}), 400

    print(f"Resgatando vale {card_code}... Processando...")
    time.sleep(1)

    try:

        update_balance_sql = text(f"UPDATE user SET balance = balance + {card.value} WHERE id = {user_id}")
        db.session.execute(update_balance_sql)

        card.is_used = True

        db.session.commit()

        user = User.query.get(user_id)
        
        return jsonify({
            "message": f"Vale de R${card.value} resgatado com sucesso!",
            "new_balance": user.balance
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"Ocorreu um erro no commit: {e}"}), 500
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- 3. ENDPOINTS DA API ---

# Endpoint para fazer login
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Faltando usuário ou senha"}), 400

    # ***** CORREÇÃO DA VULNERABILIDADE DE SQL INJECTION *****
    # Usando filter_by do SQLAlchemy para parametrizar a consulta.
    # Isso impede que a entrada do usuário seja interpretada como código SQL.
    user = User.query.filter_by(username=username, password=password).first()
    # *************************************************************

    if not user:
        return jsonify({"message": "Credenciais inválidas"}), 401

    user_id = user.id 
    token = jwt.encode({
        'sub': user_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({"token": token})

@app.route('/notes/<int:note_id>', methods=['GET'])
@limiter.limit("5 per minute")
def get_note(note_id):
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Token não encontrado"}), 401

    token = auth_header.split(" ")[1]
    try:
        # ***** CORREÇÃO DA VULNERABILIDADE JWT *****
        # Removendo options={"verify_signature": False} para que a assinatura seja verificada.
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        print(f"Token decodificado e validado: {decoded_token}")
        # Extraindo o user_id do token validado
        user_id_from_token = decoded_token['sub']
        # ***********************************************

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Token inválido"}), 401
    except Exception as e:
        return jsonify({"message": f"Erro ao decodificar token: {e}"}), 401

    note = Note.query.get(note_id)

    if not note:
        return jsonify({"message": "Anotação não encontrada"}), 404

    # ***** CORREÇÃO DA VULNERABILIDADE IDOR *****
    # Verifica se o user_id do token corresponde ao user_id da anotação
    if note.user_id != user_id_from_token:
        return jsonify({"message": "Acesso negado. Você não é o proprietário desta anotação."}), 403
    # *************************************************

    return jsonify({"id": note.id, "content": note.content, "user_id": note.user_id})

@app.route('/profile/import', methods=['POST'])
@limiter.limit("5 per minute")
def import_profile():
    encoded_data = request.data

    # ***** VULNERABILIDADE DE DESSERIALIZAÇÃO INSEGURA *****
    # O código decodifica os dados e usa pickle.loads() para reconstruir o objeto.
    # pickle é extremamente perigoso com dados de fontes não confiáveis,
    # pois o processo de desserialização pode ser instruído a executar código arbitrário.
    try:
        decoded_data = base64.b64decode(encoded_data)
        profile_object = pickle.loads(decoded_data)

        print(f"Perfil importado com sucesso: {profile_object}")
        return jsonify({"message": "Perfil importado com sucesso."}), 200

    except Exception as e:
        print(f"Falha na importação: {e}")
        return jsonify({"message": "Dados inválidos"}), 400
    # ***************************************************************

    # --- 4. INICIALIZAÇÃO DO SERVIDOR ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
