import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Importamos as tabelas e a string de conexão configuradas no Passo 3
from oauth_server import User, DATABASE_URL

# Configuração da sessão do banco de dados
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def exibir_menu():
    print("\n" + "="*45)
    print("      SISTEMA DE GERENCIAMENTO DE USUÁRIOS   ")
    print("="*45)
    print("[1] Cadastrar Novo Usuário (Incluir)")
    print("[2] Listar Todos os Usuários (Consultar Todos)")
    print("[3] Buscar Usuário por ID/Username (Consultar)")
    print("[4] Atualizar Dados de um Usuário (Alterar)")
    print("[5] Remover Usuário do Sistema (Excluir)")
    print("[0] Sair do Programa")
    print("="*45)

def incluir_usuario(db):
    print("\n--- CADASTRAR NOVO USUÁRIO ---")
    username = input("Digite o nome de usuário (username): ").strip()
    
    if not username:
        print("❌ Erro: O nome de usuário não pode ser vazio.")
        return
        
    # Verifica se o usuário já existe
    usuario_existente = db.query(User).filter(User.username == username).first()
    if usuario_existente:
        print(f"❌ Erro: Já existe um usuário cadastrado com o nome '{username}'.")
        return

    password = input("Digite a senha do usuário: ").strip()
    if len(password) < 6:
        print("❌ Erro: Por segurança, a senha deve ter pelo menos 6 caracteres.")
        return

    # Criando o registro no banco com acesso MCP ativo por padrão
    # Nota: Em produção, utilize hashes como bcrypt. Aqui mapeamos direto para a estrutura existente.
    novo_usuario = User(username=username, hashed_password=password, mcp_enabled=True)
    db.add(novo_usuario)
    db.commit()
    print(f"🟢 Sucesso! Usuário '{username}' cadastrado com o ID #{novo_usuario.id}.")

def consultar_todos(db):
    print("\n--- LISTA COMPLETA DE USUÁRIOS ---")
    usuarios = db.query(User).all()
    
    if not usuarios:
        print("Nenhum usuário cadastrado no sistema.")
        return

    print(f"{'ID':<5} | {'Nome de Usuário':<20} | {'Acesso MCP':<10}")
    print("-" * 43)
    for u in usuarios:
        status = "ATIVO" if u.mcp_enabled else "BLOQUEADO"
        print(f"{u.id:<5} | {u.username:<20} | {status:<10}")

def consultar_especifico(db):
    print("\n--- BUSCAR USUÁRIO ESPECÍFICO ---")
    busca = input("Digite o ID ou o Username do usuário: ").strip()
    
    # Tenta buscar por ID se for numérico, caso contrário busca por username
    if busca.isdigit():
        usuario = db.query(User).filter(User.id == int(busca)).first()
    else:
        usuario = db.query(User).filter(User.username == busca).first()

    if not usuario:
        print("❌ Usuário não encontrado no sistema.")
        return

    status = "PERMITIDO" if usuario.mcp_enabled else "BLOQUEADO"
    print("\nDados do Usuário Encontrado:")
    print(f"🔹 ID: {usuario.id}")
    print(f"🔹 Username: {usuario.username}")
    print(f"🔹 Status do Acesso MCP: {status}")

def alterar_usuario(db):
    print("\n--- ALTERAR DADOS DO USUÁRIO ---")
    user_id = input("Digite o ID do usuário que deseja alterar: ").strip()
    
    if not user_id.isdigit():
        print("❌ Erro: O ID deve ser um número válido.")
        return

    usuario = db.query(User).filter(User.id == int(user_id)).first()
    if not usuario:
        print("❌ Usuário não encontrado.")
        return

    print(f"Modificando dados do usuário: {usuario.username}")
    novo_username = input(f"Novo username (Deixe em branco para manter '{usuario.username}'): ").strip()
    nova_senha = input("Nova senha (Deixe em branco para manter a atual): ").strip()
    
    print("Alterar status de acesso ao MCP?")
    print("[1] Manter como está")
    print("[2] Definir como ATIVADO")
    print("[3] Definir como BLOQUEADO")
    opcao_mcp = input("Escolha o status: ").strip()

    # Aplica as alterações apenas se os campos foram preenchidos
    if novo_username:
        # Checa se o novo nome já não pertence a outro usuário
        existe_outro = db.query(User).filter(User.username == novo_username, User.id != usuario.id).first()
        if existe_outro:
            print(f"❌ Erro: O username '{novo_username}' já está em uso por outro ID.")
            return
        usuario.username = novo_username

    if nova_senha:
        if len(nova_senha) < 6:
            print("❌ Erro: Nova senha muito curta. Alteração cancelada.")
            return
        usuario.hashed_password = nova_senha

    if opcao_mcp == '2':
        usuario.mcp_enabled = True
    elif opcao_mcp == '3':
        usuario.mcp_enabled = False

    db.commit()
    print("🟢 Dados atualizados com sucesso no banco de dados!")

def excluir_usuario(db):
    print("\n--- REMOVER USUÁRIO ---")
    user_id = input("Digite o ID do usuário que deseja excluir: ").strip()
    
    if not user_id.isdigit():
        print("❌ Erro: O ID deve ser um número válido.")
        return

    id_num = int(user_id)
    if id_num == 1:
        print("❌ Erro de Segurança: O usuário administrador principal (ID #1) não pode ser removido.")
        return

    usuario = db.query(User).filter(User.id == id_num).first()
    if not usuario:
        print("❌ Usuário não encontrado.")
        return

    confirmar = input(f"⚠️ Atenção! Tem certeza de que deseja apagar permanentemente o usuário '{usuario.username}'? (S/N): ").strip().upper()
    if confirmar == 'S':
        db.delete(usuario)
        db.commit()
        print("🟢 Usuário removido com sucesso do banco central!")
    else:
        print("Operação cancelada pelo administrador.")

def main():
    db = SessionLocal()
    try:
        while True:
            exibir_menu()
            opcao = input("Selecione uma opção do menu: ").strip()
            
            if opcao == '1':
                incluir_usuario(db)
            elif opcao == '2':
                consultar_todos(db)
            elif opcao == '3':
                consultar_especifico(db)
            elif opcao == '4':
                alterar_usuario(db)
            elif opcao == '5':
                excluir_usuario(db)
            elif opcao == '0':
                print("\nEncerrando o sistema de gerenciamento. Até logo!")
                break
            else:
                print("❌ Opção inválida. Tente um número listado no menu.")
    finally:
        db.close()

if __name__ == "__main__":
    main()
