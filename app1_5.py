# app1.5.py

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
import json
import logging
from waf import waf_protection


# --- 1. CONFIGURAÇÃO INICIAL ---
app = Flask(__name__)

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

# Configuração do banco de dados SQLite (será um arquivo chamado database.db)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Chave secreta para assinar os tokens JWT. Em produção, isso deve ser um segredo!
app.config['SECRET_KEY'] = 'minha-chave-super-secreta'

# Inicializa a extensão do banco de dados
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
def get_me():
    user = User.query.get(1)
    if not user:
        return jsonify({"message": "Usuário não encontrado"}), 404
    return jsonify({"username": user.username, "balance": user.balance})

@app.route('/giftcard/redeem', methods=['POST'])
def redeem_gift_card():
    user_id = 1 # Simula que o pedido é sempre da Alice
    data = request.get_json()
    card_code = data.get('code')

    card = GiftCard.query.filter_by(code=card_code).first()

    if not card:
        return jsonify({"message": "Vale-presente não encontrado"}), 404

    # A verificação vulnerável continua aqui. Todas as threads passarão.
    if card.is_used:
        return jsonify({"message": "Este vale-presente já foi resgatado"}), 400

    print(f"Resgatando vale {card_code}... Processando...")
    time.sleep(1)

    try:

        update_balance_sql = text(f"UPDATE user SET balance = balance + {card.value} WHERE id = {user_id}")
        db.session.execute(update_balance_sql)

        card.is_used = True

        db.session.commit()

        # 4. Pega o saldo mais recente do usuário para retornar na resposta
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
    # Chave estrangeira para ligar a nota ao seu dono
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- 3. ENDPOINTS DA API ---

# Endpoint para fazer login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Faltando usuário ou senha"}), 400

    # ***** CORREÇÃO DA VULNERABILIDADE DE SQL INJECTION AQUI *****
    # Usando filter_by do SQLAlchemy para parametrizar a consulta.
    # Isso impede que a entrada do usuário seja interpretada como código SQL.
    user = User.query.filter_by(username=username, password=password).first()
    # *************************************************************

    if not user:
        return jsonify({"message": "Credenciais inválidas"}), 401

    # O 'user' aqui é um objeto User, então acessamos o ID pela propriedade .id
    user_id = user.id 
    token = jwt.encode({
        'sub': user_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({"token": token})

# Endpoint para buscar uma anotação específica
@app.route('/notes/<int:note_id>', methods=['GET'])
def get_note(note_id):
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Token não encontrado"}), 401

    token = auth_header.split(" ")[1]
    try:
        # ***** CORREÇÃO DA VULNERABILIDADE JWT AQUI (já corrigido anteriormente) *****
        # Removendo options={"verify_signature": False} para que a assinatura seja verificada.
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        print(f"Token decodificado e validado: {decoded_token}")
        # Extraindo o user_id do token validado
        user_id_from_token = decoded_token['sub']
        # **************************************************************************

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Token inválido"}), 401
    except Exception as e:
        return jsonify({"message": f"Erro ao decodificar token: {e}"}), 401

    note = Note.query.get(note_id)

    if not note:
        return jsonify({"message": "Anotação não encontrada"}), 404

    # ***** CORREÇÃO DA VULNERABILIDADE IDOR AQUI *****
    # Verifica se o user_id do token corresponde ao user_id da anotação
    if note.user_id != user_id_from_token:
        return jsonify({"message": "Acesso negado. Você não é o proprietário desta anotação."}), 403
    # *************************************************

    return jsonify({"id": note.id, "content": note.content, "user_id": note.user_id})

# --- 4. INICIALIZAÇÃO DO SERVIDOR ---
if __name__ == '__main__':
    # Cria as tabelas no banco de dados se elas não existirem
    with app.app_context():
        db.create_all()
    app.run(debug=True) # debug=True nos ajuda a ver os erros no terminal

@app.route('/profile/import', methods=['POST'])
def import_profile():
    # O endpoint agora espera receber os dados do perfil em formato JSON,
    # que é um formato de dados seguro e amplamente utilizado.
    # Não há necessidade de codificação Base64 se o cliente enviar JSON diretamente.
    try:
        # ***** CORREÇÃO DA VULNERABILIDADE DE DESSERIALIZAÇÃO INSEGURA AQUI *****
        # Em vez de pickle.loads(), usamos request.get_json() para parsear JSON.
        # Isso garante que apenas dados JSON válidos sejam processados,
        # impedindo a execução de código arbitrário.
        profile_data = request.get_json()

        # Verifica se os dados JSON foram recebidos corretamente
        if profile_data is None:
            return jsonify({"message": "Dados JSON inválidos ou ausentes"}), 400

        # Apenas para simular o uso dos dados do perfil
        print(f"Perfil importado com sucesso: {profile_data}")
        return jsonify({"message": "Perfil importado com sucesso.", "profile": profile_data}), 200

    except Exception as e:
        print(f"Falha na importação: {e}")
        return jsonify({"message": f"Dados inválidos ou erro no processamento: {e}"}), 400
    # *************************************************************************
