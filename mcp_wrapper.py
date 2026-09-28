import os
import sys
import json
import time
import subprocess
import requests
import jwt

TOKEN_FILE = os.path.expanduser("~/.meu_mcp_auth.json")
OAUTH_TOKEN_URL = "http://localhost:8000/oauth/token"

def gerenciar_sessao_e_obter_token():
    if not os.path.exists(TOKEN_FILE):
        return None

    with open(TOKEN_FILE, "r") as f:
        dados = json.load(f)

    access_token = dados.get("access_token")
    refresh_token = dados.get("refresh_token")

    try:
        # Decodifica sem checar a assinatura apenas para ler o "exp" local rapidamente
        payload = jwt.decode(access_token, options={"verify_signature": False})
        
        # Se faltarem menos de 120 segundos (2 minutos) para expirar, força a renovação preventiva
        if payload["exp"] - time.time() < 120:
            raise jwt.ExpiredSignatureError
            
        return access_token
    except (jwt.ExpiredSignatureError, jwt.DecodeError):
        # O Access Token expirou ou está prestes a expirar. Hora de usar o Refresh Token!
        try:
            res = requests.post(OAUTH_TOKEN_URL, json={
                "grant_type": "refresh_token",
                "client_id": "claude_desktop",
                "refresh_token": refresh_token
            }, timeout=4) # Timeout curto para nunca travar a inicialização do Claude se houver instabilidade de rede
            
            if res.status_code == 200:
                novos_dados = res.json()
                with open(TOKEN_FILE, "w") as f:
                    json.dump(novos_dados, f)
                return novos_dados["access_token"]
        except Exception:
            # Fallback emergencial: Se o servidor central OAuth estiver fora do ar temporariamente,
            # devolve o token atual para tentar operar em modo degradado caso ainda esteja válido
            return access_token
    return None

def main():
    access_token = gerenciar_sessao_e_obter_token()
    if not access_token:
        print("Erro: Acesso não configurado ou sessão totalmente inválida. Execute mcp_client_setup.py", file=sys.stderr)
        sys.exit(1)

    # Injeta o token válido nas variáveis de ambiente do processo filho
    env = os.environ.copy()
    env["MCP_ACCESS_TOKEN"] = access_token

    # Descobre o caminho absoluto da pasta atual para chamar o servidor MCP real com segurança
    script_dir = os.path.dirname(os.path.abspath(__file__))
    server_path = os.path.join(script_dir, "mcp_server_real.py")

    # Executa o servidor MCP real interligando os canais normais de Entrada/Saída Padrão (Stdio)
    processo = subprocess.Popen(
        [sys.executable, server_path],
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
        env=env
    )
    processo.wait()

if __name__ == "__main__":
    main()
