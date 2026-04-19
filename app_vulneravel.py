from fastapi import FastAPI, Query
import sqlite3
from typing import List, Dict

app = FastAPI(title="App Vulnerável a SQL Injection")

# Criar banco de dados e tabela de exemplo
def init_database():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Criar tabela de usuários
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    
    # Inserir dados de exemplo
    cursor.execute("DELETE FROM users")  # Limpar dados existentes
    sample_users = [
        ("admin", "admin@example.com", "admin123", "admin"),
        ("joao", "joao@example.com", "senha123", "user"),
        ("maria", "maria@example.com", "abc456", "user"),
        ("pedro", "pedro@example.com", "xyz789", "user"),
    ]
    
    for user in sample_users:
        cursor.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)", user)
    
    conn.commit()
    conn.close()

# Rota vulnerável a SQL Injection
@app.get("/users/search-vulnerable")
async def search_users_vulnerable(
    username: str = Query(..., min_length=1, description="Nome do usuário para buscar")
) -> List[Dict]:
    """
    ⚠️ ROTA VULNERÁVEL - NUNCA FAÇA ISSO EM PRODUÇÃO ⚠️
    Esta rota é propositalmente vulnerável a SQL Injection para demonstração
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # 🔴 PROBLEMA AQUI: Concatenação direta de input do usuário na query SQL
    # Isso permite SQL Injection!
    query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
    
    print(f"[VULNERÁVEL] Executando query: {query}")
    
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1], 
                "email": row[2],
                "role": row[3]
            })
        
        conn.close()
        return users
    except Exception as e:
        conn.close()
        return {"error": f"Erro na consulta: {str(e)}"}

# Rota segura (para comparação)
@app.get("/users/search-safe")
async def search_users_safe(
    username: str = Query(..., min_length=1, description="Nome do usuário para buscar")
) -> List[Dict]:
    """
    ✅ ROTA SEGURA - Usando parâmetros parametrizados
    Esta implementação NÃO é vulnerável a SQL Injection
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # 🟢 CORRETO: Usar placeholders (?) e passar parâmetros separadamente
    query = "SELECT id, username, email, role FROM users WHERE username = ?"
    
    print(f"[SEGURO] Executando query: {query} com parâmetro: {username}")
    
    cursor.execute(query, (username,))
    results = cursor.fetchall()
    
    users = []
    for row in results:
        users.append({
            "id": row[0],
            "username": row[1],
            "email": row[2], 
            "role": row[3]
        })
    
    conn.close()
    return users

# Rota de informações do sistema (útil para demonstrar impacto do SQL Injection)
@app.get("/system/info")
async def system_info():
    """Mostra informações do sistema - alvo para ataques UNION"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Buscar versão do SQLite
    cursor.execute("SELECT sqlite_version()")
    version = cursor.fetchone()[0]
    
    # Buscar tabelas do banco
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        "database_version": version,
        "tables": tables,
        "note": "Estas informações ajudam atacantes a planejar ataques mais sofisticados"
    }

# Inicializar banco de dados ao iniciar
@app.on_event("startup")
async def startup_event():
    init_database()
    print("Banco de dados inicializado com sucesso!")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)