# app.py

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import jwt # PyJWT
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from sqlalchemy import text 
import pickle
import base64
import os 
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

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def is_sql_injection_attempt(value):
    if value is None:
        return False
    patterns = ["'", "\"", "--", ";", " OR ", " AND ", "="]
    return any(pat in value.upper() for pat in patterns)

# --- 3. ENDPOINTS DA API ---

# Endpoint para fazer login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json(force=True)
    except Exception:
        app.logger.warning(f"[ERRO JSON] IP: {request.remote_addr} | Body inválido recebido")
        return jsonify({"message": "Formato JSON inválido"}), 400
    username = data.get('username')
    password = data.get('password')
    app.logger.info(f"Login attempt: username={username}, password={password}")


    if not username or not password:
        return jsonify({"message": "Faltando usuário ou senha"}), 400

    if is_sql_injection_attempt(username) or is_sql_injection_attempt(password):
        app.logger.warning(f"[SUSPEITA SQLi] IP: {request.remote_addr} | Username: {username} | Password: {password}")
    else:
        app.logger.info(f"[LOGIN] IP: {request.remote_addr} | username={username} | password={password}")

    # ***** VULNERABILIDADE DE SQL INJECTION AQUI *****
    # A query está sendo montada com concatenação de strings.
    # Isso permite que um atacante injete comandos SQL.
    query_sql = text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'")
    result = db.session.execute(query_sql)
    user = result.fetchone()
    # *************************************************

    if not user:
        return jsonify({"message": "Credenciais inválidas"}), 401

    # O 'user' aqui é uma tuple, então acessamos o ID pelo índice 0
    user_id = user[0] 
    token = jwt.encode({
        'sub': user_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({"token": token})

# Endpoint para buscar uma anotação específica
# app.py

@app.route('/notes/<int:note_id>', methods=['GET'])
def get_note(note_id):
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"message": "Token não encontrado"}), 401

    # ***** VULNERABILIDADE JWT AQUI *****
    # O token é pego do cabeçalho
    token = auth_header.split(" ")[1]
    try:
        decoded_token_UNSAFE = jwt.decode(token, options={"verify_signature": False})
        print(f"Token decodificado sem validação: {decoded_token_UNSAFE}") # Log para vermos o ataque
    except Exception as e:
        return jsonify({"message": f"Token inválido: {e}"}), 401
    # ***********************************

    note = Note.query.get(note_id)

    if not note:
        return jsonify({"message": "Anotação não encontrada"}), 404

    # A validação de IDOR ainda pode (e deve) ser feita aqui depois
    return jsonify({"id": note.id, "content": note.content})


@app.route('/profile/import', methods=['POST'])
def import_profile():
    # O endpoint espera receber os dados do perfil em formato de texto,
    # codificados em Base64 para transporte seguro.
    encoded_data = request.data

    # ***** VULNERABILIDADE DE DESSERIALIZAÇÃO INSEGURA AQUI *****
    # O código decodifica os dados e usa pickle.loads() para reconstruir o objeto.
    # pickle é extremamente perigoso com dados de fontes não confiáveis,
    # pois o processo de desserialização pode ser instruído a executar código arbitrário.
    try:
        decoded_data = base64.b64decode(encoded_data)
        profile_object = pickle.loads(decoded_data)

        # Apenas para simular o uso do objeto
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
