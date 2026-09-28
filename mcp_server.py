import os
import sys
import jwt
import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Servidor MCP Protegido com API de Dados")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, "public_key.pem"), "r") as f:
    PUBLIC_KEY = f.read()

API_URL = "http://localhost:8000/api/notes"

def obter_token_ambiente() -> str:
    token = os.environ.get("MCP_ACCESS_TOKEN")
    if not token:
        print("Erro Interno: Variável MCP_ACCESS_TOKEN ausente.", file=sys.stderr)
        raise PermissionError("Não autenticado.")
    return token

@mcp.tool()
def ler_minhas_notas_sensiveis() -> str:
    """Busca com segurança todas as notas pessoais e corporativas do usuário logado no banco de dados central."""
    try:
        # 1. Recupera o token injetado pelo Wrapper
        token = obter_token_ambiente()
        
        # 2. Faz uma requisição segura para o backend central usando o token do usuário
        headers = {"Authorization": f"Bearer {token}"}
        resposta = requests.get(API_URL, headers=headers, timeout=5)
        
        if resposta.status_code == 200:
            notas = resposta.json()
            if not notas:
                return "Você autenticou com sucesso, mas não possui nenhuma nota cadastrada no banco."
            
            resultado = "=== SUAS NOTAS PRIVADAS ENCONTRADAS NO BANCO ===\n"
            for nota in notas:
                resultado += f"\n📌 Título: {nota['title']}\n📝 Conteúdo: {nota['content']}\n"
            return resultado
        else:
            return f"Erro ao acessar os dados no servidor central: Código {resposta.status_code}"
            
    except PermissionError as e:
        return f"[Acesso Negado]: {str(e)}"
    except Exception as e:
        return f"Erro de comunicação com o banco de dados: {str(e)}"

if __name__ == "__main__":
    mcp.run()
