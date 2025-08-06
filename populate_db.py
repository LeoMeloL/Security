# populate_db.py

from app import app, db, User, Note
#from app1_1 import app, db, User, Note, GiftCard

# Executar este script irá apagar os dados antigos e criar novos.
with app.app_context():
    # Apaga tudo para garantir um estado limpo
    db.drop_all()
    db.create_all()

    # Cria dois usuários
    alice = User(username='alice', password='password123')
    bob = User(username='bob', password='password456')

    db.session.add(alice)
    db.session.add(bob)
    db.session.commit() # Salva os usuários para que eles tenham IDs

    # Cria anotações para cada usuário
    note_alice = Note(content="Minha anotação secreta sobre o projeto.", user_id=alice.id)
    note_bob = Note(content="Lembrar de comprar leite. Senha do Wifi: MeuWifi@123", user_id=bob.id)

    db.session.add(note_alice)
    db.session.add(note_bob)

    gift_card = GiftCard(code='VALE50', value=50.0, is_used=False)
    db.session.add(gift_card)

    db.session.commit() # Salva as anotações

    print("Banco de dados populado com Alice e Bob!")
    print(f"ID da nota da Alice: {note_alice.id}") # Provavelmente 1
    print(f"ID da nota do Bob: {note_bob.id}")   # Provavelmente 2
    print(f"Vale-presente 'VALE50' criado com sucesso.")
