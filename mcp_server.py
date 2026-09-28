import os
import sys
import jwt
from mcp.server.fastmcp import FastMCP

# Inicializa o servidor FastMCP
mcp = FastMCP("Servidor MCP Protegido por BD")

# Carrega a chave pública para VERIFICAR a autenticidade e integridade dos tokens
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, "public_key.pem"), "r") as f:
    PUBLIC_KEY = f.read()

def obter_id_do_usuario_autenticado() -> int:
    """
    Recupera o token injetado pelo Wrapper, valida a assinatura assimétrica
    e extrai o ID do usuário diretamente da claim 'sub' (sem tocar no banco).
    """
    token = os.environ.get("MCP_ACCESS_TOKEN")
    if not token:
        print("Erro Interno: Variável MCP_ACCESS_TOKEN ausente.", file=sys.stderr)
        raise PermissionError("Não autenticado.")
        
    try:
        # Decodificação assimétrica segura usando o algoritmo RS256 e a chave PÚBLICA
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
        return int(payload["sub"])
    except jwt.ExpiredSignatureError:
        print("Erro: Token apresentado já expirou.", file=sys.stderr)
        raise PermissionError("Sessão expirada no servidor central.")
    except jwt.PyJWTError as e:
        print(f"Erro de Validação de Token: {e}", file=sys.stderr)
        raise PermissionError("Token inválido ou adulterado.")

# --- EXPOSIÇÃO DE FERRAMENTA (TOOL) PARA A IA ---

@mcp.tool()
def executar_acao_privada() -> str:
    """Executa tarefas personalizadas e confidenciais com base nas credenciais do usuário logado."""
    try:
        # Extrai o ID com custo zero de banco e validação matemática instantânea
        user_id = obter_id_do_usuario_autenticado()
        return f"[Sucesso] Requisição aceita. O seu ID de usuário verificado no banco de dados central é #{user_id}."
    except PermissionError as e:
        return f"[Acesso Negado]: {str(e)}"

if __name__ == "__main__":
    # Inicializa o ciclo de vida nativo do servidor MCP sob Stdio
    mcp.run()
