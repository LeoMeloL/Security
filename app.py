# app.py

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import jwt # PyJWT
from datetime import datetime, timedelta
from sqlalchemy import text # Importe o 'text'
import pickle
import base64
import os # Importe o 'os' para a demonstração do ataque

# --- 1. CONFIGURAÇÃO INICIAL ---
app = Flask(__name__)

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
    # ATENÇÃO: Em um projeto real, NUNCA guarde senhas em texto plano.
    # Use bibliotecas como Werkzeug ou passlib para gerar e verificar hashes.
    password = db.Column(db.String(80), nullable=False)

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

# --- 4. INICIALIZAÇÃO DO SERVIDOR ---
if __name__ == '__main__':
    # Cria as tabelas no banco de dados se elas não existirem
    with app.app_context():
        db.create_all()
    app.run(debug=True) # debug=True nos ajuda a ver os erros no terminal

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