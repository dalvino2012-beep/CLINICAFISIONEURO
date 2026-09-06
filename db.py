import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "clinica.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"
BACKUP_DIR = Path(__file__).parent / "backups"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def backup_diario():
    """Cria uma cópia de segurança do banco uma vez por dia (histórico preservado)."""
    if not DB_PATH.exists():
        return
    import shutil
    from datetime import date
    BACKUP_DIR.mkdir(exist_ok=True)
    destino = BACKUP_DIR / f"clinica_{date.today().isoformat()}.db"
    if not destino.exists():
        try:
            shutil.copy2(DB_PATH, destino)
        except OSError:
            pass


def fazer_backup():
    """Backup manual imediato (cópia consistente com data e hora). Retorna o nome do arquivo."""
    if not DB_PATH.exists():
        return None
    from datetime import datetime
    BACKUP_DIR.mkdir(exist_ok=True)
    nome = f"clinica_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.db"
    destino = BACKUP_DIR / nome
    origem = sqlite3.connect(DB_PATH)
    copia = sqlite3.connect(destino)
    try:
        with copia:
            origem.backup(copia)   # cópia consistente mesmo com o sistema em uso
    finally:
        copia.close()
        origem.close()
    return nome


def init_db():
    from werkzeug.security import generate_password_hash

    is_new = not DB_PATH.exists()
    conn = get_db()
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))

    # Migrações: adiciona colunas novas em bancos criados antes dessas versões
    def add_col(tabela, coluna, definicao):
        cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({tabela})").fetchall()]
        if coluna not in cols:
            conn.execute(f"ALTER TABLE {tabela} ADD COLUMN {coluna} {definicao}")

    add_col("pacientes", "observacoes", "TEXT")
    add_col("medicos", "sala", "TEXT")
    add_col("usuarios", "medico_id", "INTEGER")
    add_col("consultas", "tipo_atendimento", "TEXT DEFAULT 'particular'")
    add_col("consultas", "convenio", "TEXT")
    add_col("pacientes", "whatsapp", "INTEGER DEFAULT 0")
    add_col("pacientes", "cep", "TEXT")
    add_col("pacientes", "email", "TEXT")
    add_col("receitas", "impresso_em", "TEXT")
    add_col("pacientes", "tipo_atendimento", "TEXT DEFAULT 'particular'")
    add_col("pacientes", "convenio", "TEXT")
    add_col("contas_receber", "data_recebimento", "TEXT")
    add_col("contas_receber", "modalidade", "TEXT DEFAULT 'convenio'")
    add_col("contas_receber", "hora", "TEXT")
    add_col("contas_receber", "bandeira", "TEXT")
    add_col("caixa_entradas", "banco_id", "INTEGER")
    add_col("caixa_saidas", "banco_id", "INTEGER")
    conn.commit()

    if is_new:
        conn.execute(
            "INSERT INTO usuarios (nome, login, senha_hash, perfil) VALUES (?, ?, ?, ?)",
            ("Administrador", "admin", generate_password_hash("admin123"), "admin"),
        )
        conn.commit()
    conn.close()
