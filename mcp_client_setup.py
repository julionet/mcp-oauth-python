import time
import requests
import json
import os

TOKEN_FILE = os.path.expanduser("~/.meu_mcp_auth.json")
BASE_URL = "http://localhost:8000"

def realizar_login():
    print("Iniciando fluxo de pareamento com o banco central...")
    try:
        res = requests.post(f"{BASE_URL}/oauth/device/authorize", json={
            "client_id": "claude_desktop",
            "scope": "mcp:tools"
        }).json()
    except requests.exceptions.ConnectionError:
        print("Erro: O Servidor OAuth não está rodando na porta 8000. Inicie-o primeiro!")
        return

    print(f"\n Abra o link no navegador para validar suas permissões: {res['verification_uri']}")
    print("Aguardando aprovação no painel web...")

    device_code = res["device_code"]
    interval = res["interval"]

    while True:
        time.sleep(interval)
        token_res = requests.post(f"{BASE_URL}/oauth/token", json={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": "claude_desktop",
            "device_code": device_code
        })
        
        dados = token_res.json()
        if token_res.status_code == 200:
            with open(TOKEN_FILE, "w") as f:
                json.dump(dados, f)
            print("\n Sucesso! Usuário validado no banco de dados e autorizado no sistema.")
            break
        elif dados.get("detail") == "authorization_pending":
            continue
        else:
            print(f"\n Falha no fluxo: {dados.get('detail')}")
            break

if __name__ == "__main__":
    realizar_login()
