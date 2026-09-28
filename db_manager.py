import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
# Importamos as classes diretamente do servidor OAuth que criamos no Passo 3
from oauth_server import User, DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def listar_usuarios(db):
    usuarios = db.query(User).all()
    print("\n=== LISTA DE USUÁRIOS NO BANCO CENTRAL ===")
    print(f"{'ID':<5} | {'Usuário':<15} | {'Status MCP':<12}")
    print("-" * 40)
    for u in usuarios:
        status = "ATIVADO" if u.mcp_enabled else "BLOQUEADO"
        print(f"{u.id:<5} | {u.username:<15} | {status:<12}")
    print("=" * 40 + "\n")

def alterar_status_usuario():
    db = SessionLocal()
    try:
        listar_usuarios(db)
        
        id_input = input("Digite o ID do usuário que deseja gerenciar (ou 'sair' para encerrar): ").strip()
        if id_input.lower() == 'sair':
            return

        try:
            user_id = int(id_input)
        except ValueError:
            print("❌ Erro: ID inválido. Digite um número inteiro.")
            return

        usuario = db.query(User).filter(User.id == user_id).first()
        if not usuario:
            print(f"❌ Erro: Usuário com ID #{user_id} não foi encontrado.")
            return

        print(f"\nUsuário selecionado: {usuario.username}")
        print(f"Status atual do MCP: {'ATIVADO' if usuario.mcp_enabled else 'BLOQUEADO'}")
        
        opcao = input("Deseja [1] ATIVAR ou [2] BLOQUEAR este usuário? Digite a opção: ").strip()
        
        if opcao == '1':
            usuario.mcp_enabled = True
            db.commit()
            print(f"🟢 Sucesso! O usuário '{usuario.username}' agora tem acesso PERMITIDO ao MCP.")
        elif opcao == '2':
            usuario.mcp_enabled = False
            db.commit()
            print(f"🔴 Sucesso! O usuário '{usuario.username}' foi BLOQUEADO e não acessa mais o MCP.")
        else:
            print("❌ Opção inválida. Nenhuma alteração foi feita.")

    finally:
        db.close()

if __name__ == "__main__":
    alterar_status_usuario()
