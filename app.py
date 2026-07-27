import uuid
from datetime import date
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, g,
    send_from_directory, abort,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from db import get_db, init_db, backup_diario, fazer_backup, BACKUP_DIR

app = Flask(__name__)
app.secret_key = "troque-esta-chave-em-producao-vitalis-clinica"

# Não deixar o navegador guardar versões antigas das telas/CSS/imagens.
# Assim o usuário sempre vê a versão mais nova sem precisar de janela anônima
# (Ctrl+Shift+N) nem limpar cache. Custo: recarrega os arquivos a cada acesso,
# irrelevante na rede local da clínica.
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
app.config["TEMPLATES_AUTO_RELOAD"] = True


@app.after_request
def _sem_cache(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

UPLOAD_FOLDER = Path(__file__).parent / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB por arquivo
EXTENSOES_PERMITIDAS = {
    "pdf", "png", "jpg", "jpeg", "gif", "bmp", "webp",
    "doc", "docx", "txt", "xls", "xlsx", "csv",
}


def _extensao_ok(nome):
    return "." in nome and nome.rsplit(".", 1)[1].lower() in EXTENSOES_PERMITIDAS


def _salvar_anexos(db, paciente_id):
    arquivos = request.files.getlist("anexos")
    for arquivo in arquivos:
        if not arquivo or not arquivo.filename:
            continue
        if not _extensao_ok(arquivo.filename):
            flash(f"Arquivo '{arquivo.filename}' ignorado (tipo não permitido).", "error")
            continue
        nome_original = secure_filename(arquivo.filename)
        ext = nome_original.rsplit(".", 1)[1].lower()
        nome_arquivo = f"{uuid.uuid4().hex}.{ext}"
        arquivo.save(UPLOAD_FOLDER / nome_arquivo)
        descricao = request.form.get("descricao_anexo", "").strip()
        db.execute(
            "INSERT INTO anexos (paciente_id, nome_original, nome_arquivo, descricao) VALUES (?, ?, ?, ?)",
            (paciente_id, nome_original, nome_arquivo, descricao),
        )
    db.commit()


@app.before_request
def load_logged_in_user():
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        db = get_db()
        g.user = db.execute("SELECT * FROM usuarios WHERE id = ?", (user_id,)).fetchone()
        db.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        if g.user["perfil"] != "admin":
            flash("Acesso restrito ao administrador.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


def medico_required(view):
    """Apenas usuários com perfil de médico (o médico do paciente)."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        if g.user["perfil"] != "medico":
            flash("Apenas o médico do paciente pode emitir/imprimir receitas.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


def is_medico():
    return g.user is not None and g.user["perfil"] == "medico"


def is_admin_user():
    return g.user is not None and g.user["perfil"] == "admin"


def pode_receita():
    """Quem pode abrir/emitir/imprimir receitas: médico ou administrador."""
    return g.user is not None and g.user["perfil"] in ("medico", "admin")


def receita_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        if not pode_receita():
            flash("Apenas o médico ou o administrador podem emitir/imprimir receitas.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


def medico_id_atual():
    """ID do cadastro de médico vinculado ao usuário logado (ou None)."""
    if not is_medico():
        return None
    try:
        return g.user["medico_id"]
    except (IndexError, KeyError):
        return None


def paciente_acessivel(db, paciente_id):
    """Admin/recepção acessam todos; médico só acessa seus pacientes vinculados."""
    if not is_medico():
        return True
    mid = medico_id_atual()
    if not mid:
        return False
    return db.execute(
        "SELECT 1 FROM medico_pacientes WHERE medico_id = ? AND paciente_id = ?",
        (mid, paciente_id),
    ).fetchone() is not None


# expõe para os templates
app.jinja_env.globals["is_medico"] = is_medico
app.jinja_env.globals["pode_receita"] = pode_receita


# ---------- Autenticação ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    trocar = request.args.get("como", "").strip()  # "entrar como" um médico específico (menu Médicos)
    if g.user is not None:
        if trocar:
            # sai do usuário atual para o médico entrar com a senha dele
            session.clear()
            return redirect(url_for("login", como=trocar))
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        login_ = request.form.get("login", "").strip()
        senha = request.form.get("senha", "").strip()
        db = get_db()
        # login não diferencia maiúsculas/minúsculas (evita erro de teclado que capitaliza)
        user = db.execute("SELECT * FROM usuarios WHERE login = ? COLLATE NOCASE", (login_,)).fetchone()
        db.close()
        if user is None or not check_password_hash(user["senha_hash"], senha):
            flash("Login ou senha inválidos.", "error")
        elif not user["ativo"]:
            flash("Usuário inativo. Contate o administrador.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            # médico já cai na busca de pacientes; os demais no painel
            if request.args.get("next"):
                return redirect(request.args.get("next"))
            if user["perfil"] == "medico":
                return redirect(url_for("pacientes_lista"))
            return redirect(url_for("dashboard"))
    # lista de médicos com login, para a seleção rápida na tela de entrada
    db = get_db()
    medicos_login = db.execute(
        """SELECT u.login, u.nome FROM usuarios u
           WHERE u.perfil = 'medico' AND u.ativo = 1
           ORDER BY u.nome"""
    ).fetchall()
    db.close()
    return render_template("login.html", medicos_login=medicos_login, pre_login=trocar)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/alterar-senha", methods=["GET", "POST"])
@login_required
def alterar_senha():
    if request.method == "POST":
        atual = request.form.get("senha_atual", "")
        nova = request.form.get("nova_senha", "")
        confirmar = request.form.get("confirmar_senha", "")
        if not check_password_hash(g.user["senha_hash"], atual):
            flash("Senha atual incorreta.", "error")
        elif len(nova) < 6:
            flash("A nova senha deve ter ao menos 6 caracteres.", "error")
        elif nova != confirmar:
            flash("A confirmação não confere com a nova senha.", "error")
        else:
            db = get_db()
            db.execute(
                "UPDATE usuarios SET senha_hash = ? WHERE id = ?",
                (generate_password_hash(nova), g.user["id"]),
            )
            db.commit()
            db.close()
            flash("Senha alterada com sucesso.", "success")
            return redirect(url_for("dashboard"))
    return render_template("alterar_senha.html")


# ---------- Dashboard ----------

@app.route("/")
@login_required
def dashboard():
    db = get_db()
    hoje = date.today().isoformat()
    total_pacientes = db.execute("SELECT COUNT(*) c FROM pacientes").fetchone()["c"]
    total_medicos = db.execute("SELECT COUNT(*) c FROM medicos WHERE ativo = 1").fetchone()["c"]
    consultas_hoje = db.execute(
        "SELECT COUNT(*) c FROM consultas WHERE data = ?", (hoje,)
    ).fetchone()["c"]
    proximas = db.execute(
        """SELECT c.*, p.nome AS paciente_nome, m.nome AS medico_nome
           FROM consultas c
           JOIN pacientes p ON p.id = c.paciente_id
           JOIN medicos m ON m.id = c.medico_id
           WHERE c.data = ? AND c.status != 'cancelada'
           ORDER BY c.hora""",
        (hoje,),
    ).fetchall()
    db.close()
    return render_template(
        "dashboard.html",
        total_pacientes=total_pacientes,
        total_medicos=total_medicos,
        consultas_hoje=consultas_hoje,
        proximas=proximas,
        hoje=hoje,
    )


# ---------- Pacientes ----------

@app.route("/pacientes")
@login_required
def pacientes_lista():
    termo = request.args.get("q", "").strip()
    medico_filtro = request.args.get("medico", "").strip()
    db = get_db()
    where = []
    params = []
    if termo:
        like = f"%{termo}%"
        where.append("(p.nome LIKE ? OR p.cpf LIKE ?)")
        params += [like, like]
    medico_ctx = None
    if is_medico():
        # médico logado: sempre só os seus pacientes
        mid = medico_id_atual()
        where.append("p.id IN (SELECT paciente_id FROM medico_pacientes WHERE medico_id = ?)")
        params.append(mid or -1)
    elif medico_filtro:
        # admin abriu um médico pelo combo: mostra os pacientes daquele médico
        where.append("p.id IN (SELECT paciente_id FROM medico_pacientes WHERE medico_id = ?)")
        params.append(medico_filtro)
        medico_ctx = db.execute("SELECT * FROM medicos WHERE id = ?", (medico_filtro,)).fetchone()
    sql = "SELECT p.* FROM pacientes p"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY p.nome"
    rows = db.execute(sql, params).fetchall()
    db.close()
    return render_template("pacientes_lista.html", pacientes=rows, termo=termo, medico_ctx=medico_ctx)


@app.route("/pacientes/novo", methods=["GET", "POST"])
@login_required
def pacientes_novo():
    if request.method == "POST":
        dados = _ler_form_paciente()
        db = get_db()
        try:
            cur = db.execute(
                """INSERT INTO pacientes (nome, cpf, data_nascimento, telefone, endereco, historico, observacoes)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (dados["nome"], dados["cpf"], dados["data_nascimento"], dados["telefone"], dados["endereco"], dados["historico"], dados["observacoes"]),
            )
            novo_id = cur.lastrowid
            db.commit()
            _salvar_anexos(db, novo_id)
            flash("Paciente cadastrado com sucesso.", "success")
            return redirect(url_for("pacientes_editar", paciente_id=novo_id))
        except db.IntegrityError:
            flash("Já existe um paciente com este CPF.", "error")
        finally:
            db.close()
    return render_template("pacientes_form.html", paciente=None, anexos=[], receitas=[], evolucoes=[], minha_sala="")


@app.route("/pacientes/<int:paciente_id>/editar", methods=["GET", "POST"])
@login_required
def pacientes_editar(paciente_id):
    db = get_db()
    paciente = db.execute("SELECT * FROM pacientes WHERE id = ?", (paciente_id,)).fetchone()
    if paciente is None:
        db.close()
        flash("Paciente não encontrado.", "error")
        return redirect(url_for("pacientes_lista"))
    if not paciente_acessivel(db, paciente_id):
        db.close()
        flash("Este paciente não está vinculado a você.", "error")
        return redirect(url_for("pacientes_lista"))
    if request.method == "POST":
        dados = _ler_form_paciente()
        try:
            db.execute(
                """UPDATE pacientes SET nome=?, cpf=?, data_nascimento=?, telefone=?, endereco=?, historico=?, observacoes=?
                   WHERE id=?""",
                (dados["nome"], dados["cpf"], dados["data_nascimento"], dados["telefone"], dados["endereco"], dados["historico"], dados["observacoes"], paciente_id),
            )
            db.commit()
            _salvar_anexos(db, paciente_id)
            flash("Dados do paciente atualizados.", "success")
            db.close()
            return redirect(url_for("pacientes_editar", paciente_id=paciente_id))
        except db.IntegrityError:
            flash("Já existe um paciente com este CPF.", "error")
        paciente = db.execute("SELECT * FROM pacientes WHERE id = ?", (paciente_id,)).fetchone()
    anexos = db.execute(
        "SELECT * FROM anexos WHERE paciente_id = ? ORDER BY criado_em DESC", (paciente_id,)
    ).fetchall()
    receitas = db.execute(
        """SELECT r.*, m.nome AS medico_nome FROM receitas r
           LEFT JOIN medicos m ON m.id = r.medico_id
           WHERE r.paciente_id = ? ORDER BY r.criado_em DESC""",
        (paciente_id,),
    ).fetchall()
    evolucoes = db.execute(
        """SELECT e.*, m.nome AS medico_nome FROM evolucoes e
           LEFT JOIN medicos m ON m.id = e.medico_id
           WHERE e.paciente_id = ? ORDER BY e.criado_em DESC""",
        (paciente_id,),
    ).fetchall()
    # sala sugerida no botão "Chamar no telão": a sala cadastrada do médico logado
    # (fica em branco se não houver — o médico digita a sala em que estiver na hora)
    minha_sala = ""
    if is_medico():
        mid = medico_id_atual()
        if mid:
            m = db.execute("SELECT sala FROM medicos WHERE id = ?", (mid,)).fetchone()
            minha_sala = (m["sala"] if m and m["sala"] else "") or ""
    db.close()
    return render_template("pacientes_form.html", paciente=paciente, anexos=anexos,
                           receitas=receitas, evolucoes=evolucoes, minha_sala=minha_sala)


@app.route("/pacientes/<int:paciente_id>/chamar-telao", methods=["POST"])
@login_required
def paciente_chamar_telao(paciente_id):
    db = get_db()
    paciente = db.execute("SELECT * FROM pacientes WHERE id = ?", (paciente_id,)).fetchone()
    if paciente is None:
        db.close()
        abort(404)
    if not paciente_acessivel(db, paciente_id):
        db.close()
        flash("Este paciente não está vinculado a você.", "error")
        return redirect(url_for("pacientes_lista"))
    sala = request.form.get("sala", "").strip()
    hoje = date.today().isoformat()
    medico_id = medico_id_atual()  # None se for admin/recepção
    ultimo = db.execute("SELECT MAX(numero) AS m FROM senhas WHERE data = ?", (hoje,)).fetchone()["m"]
    numero = (ultimo or 0) + 1
    db.execute(
        """INSERT INTO senhas (numero, data, paciente_id, medico_id, sala, status, chamado_em)
           VALUES (?, ?, ?, ?, ?, 'chamado', datetime('now','localtime'))""",
        (numero, hoje, paciente_id, medico_id, sala),
    )
    db.commit()
    db.close()
    primeiro = (paciente["nome"] or "").split(" ")[0]
    destino = f"sala {sala}" if sala else "o consultório"
    flash(f"📢 {primeiro} foi chamado(a) no telão para {destino}.", "success")
    return redirect(url_for("pacientes_editar", paciente_id=paciente_id))


@app.route("/anexos/<int:anexo_id>/baixar")
@login_required
def anexo_baixar(anexo_id):
    db = get_db()
    anexo = db.execute("SELECT * FROM anexos WHERE id = ?", (anexo_id,)).fetchone()
    db.close()
    if anexo is None:
        abort(404)
    return send_from_directory(
        UPLOAD_FOLDER, anexo["nome_arquivo"],
        as_attachment=True, download_name=anexo["nome_original"],
    )


@app.route("/anexos/<int:anexo_id>/excluir", methods=["POST"])
@login_required
def anexo_excluir(anexo_id):
    db = get_db()
    anexo = db.execute("SELECT * FROM anexos WHERE id = ?", (anexo_id,)).fetchone()
    if anexo is None:
        db.close()
        abort(404)
    paciente_id = anexo["paciente_id"]
    arquivo = UPLOAD_FOLDER / anexo["nome_arquivo"]
    if arquivo.exists():
        arquivo.unlink()
    db.execute("DELETE FROM anexos WHERE id = ?", (anexo_id,))
    db.commit()
    db.close()
    flash("Anexo removido.", "success")
    return redirect(url_for("pacientes_editar", paciente_id=paciente_id))


# ---------- Receitas / Solicitações médicas ----------

CLINICA_NOME = "FISIONEURO Clínica Médica"
CLINICA_INFO = (
    "Alameda Lindóia, 99 - Jardim do Lago - CEP 12947-280 - Atibaia/SP<br/>"
    "Central de atendimento: (11) 4412-2723 / (11) 4412-2805"
)
CLINICA_CNPJ = "19.428.551/0001-01"
CLINICA_SITE = "www.fisioneuro.com"
AZUL = "#0B5FA5"  # cor da faixa/identidade dos documentos
LOGO_AZUL = Path(__file__).parent / "static" / "img" / "logo_fisioneuro_azul.png"


def _faixa_azul(canvas, doc):
    """Desenha a faixa azul vertical à esquerda da folha:
    8 mm (0,8 cm) de largura, deslocada 10 mm (1,0 cm) da borda esquerda, em toda a altura."""
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor
    canvas.saveState()
    canvas.setFillColor(HexColor(AZUL))
    # faixa começando na borda esquerda (x = 0), 8 mm de largura, toda a altura
    canvas.rect(0, 0, 8 * mm, doc.pagesize[1], stroke=0, fill=1)
    canvas.restoreState()


def _rodape_clinica(canvas, doc):
    """Endereço + central de atendimento centralizados no rodapé (receita simples)."""
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(HexColor("#6b7a77"))
    linhas = [l.strip() for l in CLINICA_INFO.split("<br/>")]
    x = (doc.pagesize[0] + 8 * mm) / 2  # centraliza na área útil (depois da faixa)
    y = 8 * mm
    for linha in reversed(linhas):
        canvas.drawCentredString(x, y, linha)
        y += 10
    canvas.restoreState()


def _qr_texto_receita(r):
    """Texto que vai dentro do QR Code (dados da receita, legível ao escanear)."""
    tipo_nome = {
        "receita": "Receita", "exame": "Solicitação de exames",
        "ambos": "Receita e exames", "controlada": "Receita de Controle Especial",
    }.get(r["tipo"], "Receita")
    linhas = [
        "FISIONEURO Clínica Médica",
        f"{tipo_nome} nº {r['id']} - {r['data']}",
        f"Paciente: {r['paciente_nome']}",
        f"CPF: {r['paciente_cpf'] or '-'}",
    ]
    if r["medico_nome"]:
        linhas.append(f"Médico: {r['medico_nome']} - CRM {r['medico_crm'] or ''}")
    if r["medicamentos"]:
        linhas += ["Medicamentos:", r["medicamentos"]]
    if r["exames"]:
        linhas += ["Exames:", r["exames"]]
    linhas.append("Central de atendimento: (11) 4412-2723")
    return "\n".join(linhas)


def _qr_png_bytes(texto):
    import qrcode
    from io import BytesIO
    # preto + correção baixa = menos denso e mais fácil de escanear
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=12, border=3)
    qr.add_data(texto)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _qr_data_uri(r):
    import base64
    return "data:image/png;base64," + base64.b64encode(_qr_png_bytes(_qr_texto_receita(r))).decode()


def _receita_completa(db, receita_id):
    return db.execute(
        """SELECT r.*, p.nome AS paciente_nome, p.cpf AS paciente_cpf,
                  p.telefone AS paciente_telefone, p.data_nascimento AS paciente_nasc,
                  p.endereco AS paciente_endereco,
                  m.nome AS medico_nome, m.crm AS medico_crm, m.especialidade AS medico_especialidade
           FROM receitas r
           JOIN pacientes p ON p.id = r.paciente_id
           LEFT JOIN medicos m ON m.id = r.medico_id
           WHERE r.id = ?""",
        (receita_id,),
    ).fetchone()


@app.route("/pacientes/<int:paciente_id>/receitas/nova", methods=["GET", "POST"])
@receita_required
def receitas_nova(paciente_id):
    db = get_db()
    paciente = db.execute("SELECT * FROM pacientes WHERE id = ?", (paciente_id,)).fetchone()
    if paciente is None:
        db.close()
        flash("Paciente não encontrado.", "error")
        return redirect(url_for("pacientes_lista"))
    if not paciente_acessivel(db, paciente_id):
        db.close()
        flash("Este paciente não está vinculado a você.", "error")
        return redirect(url_for("pacientes_lista"))
    medicos = db.execute("SELECT * FROM medicos WHERE ativo = 1 ORDER BY nome").fetchall()
    if request.method == "POST":
        medico_id = request.form.get("medico_id") or None
        tipo = request.form.get("tipo", "receita")
        medicamentos = request.form.get("medicamentos", "").strip()
        exames = request.form.get("exames", "").strip()
        instrucoes = request.form.get("instrucoes", "").strip()
        evolucao = request.form.get("evolucao", "").strip()
        data_ = request.form.get("data", "").strip() or date.today().isoformat()
        if not medicamentos and not exames:
            flash("Informe ao menos um medicamento ou exame.", "error")
        else:
            cur = db.execute(
                """INSERT INTO receitas (paciente_id, medico_id, tipo, medicamentos, exames, instrucoes, data)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (paciente_id, medico_id, tipo, medicamentos, exames, instrucoes, data_),
            )
            # evolução/observações do médico vão para o prontuário (histórico permanente)
            if evolucao:
                db.execute(
                    "INSERT INTO evolucoes (paciente_id, medico_id, texto) VALUES (?, ?, ?)",
                    (paciente_id, medico_id, evolucao),
                )
            db.commit()
            db.close()
            flash("Documento gerado com sucesso.", "success")
            return redirect(url_for("receita_ver", receita_id=cur.lastrowid))
    db.close()
    return render_template(
        "receita_form.html", paciente=paciente, medicos=medicos, hoje=date.today().isoformat(),
        tipo_sel=request.args.get("tipo", "receita"),
        medico_sel=request.args.get("medico_id", type=int),
    )


@app.route("/pacientes/<int:paciente_id>/receita-rapida", methods=["POST"])
@receita_required
def receita_rapida(paciente_id):
    """Gera a receita/solicitação a partir do texto digitado direto na ficha do paciente."""
    db = get_db()
    paciente = db.execute("SELECT * FROM pacientes WHERE id = ?", (paciente_id,)).fetchone()
    if paciente is None or not paciente_acessivel(db, paciente_id):
        db.close()
        flash("Paciente não encontrado ou não vinculado a você.", "error")
        return redirect(url_for("pacientes_lista"))
    tipo = request.form.get("tipo", "receita")
    conteudo = request.form.get("conteudo", "").strip()
    if not conteudo:
        db.close()
        flash("Digite a receita ou solicitação antes de gerar.", "error")
        return redirect(url_for("pacientes_editar", paciente_id=paciente_id))
    medicamentos = conteudo if tipo != "exame" else ""
    exames = conteudo if tipo == "exame" else ""
    cur = db.execute(
        """INSERT INTO receitas (paciente_id, medico_id, tipo, medicamentos, exames, instrucoes, data)
           VALUES (?, ?, ?, ?, ?, '', ?)""",
        (paciente_id, medico_id_atual(), tipo, medicamentos, exames, date.today().isoformat()),
    )
    db.commit()
    rid = cur.lastrowid
    db.close()
    return redirect(url_for("receita_ver", receita_id=rid))


@app.route("/pacientes/<int:paciente_id>/evolucao", methods=["POST"])
@receita_required
def evolucao_add(paciente_id):
    """Salva uma evolução/observação escrita direto na ficha do paciente."""
    db = get_db()
    if not paciente_acessivel(db, paciente_id):
        db.close()
        flash("Paciente não vinculado a você.", "error")
        return redirect(url_for("pacientes_lista"))
    texto = request.form.get("texto", "").strip()
    if texto:
        db.execute(
            "INSERT INTO evolucoes (paciente_id, medico_id, texto) VALUES (?, ?, ?)",
            (paciente_id, medico_id_atual(), texto),
        )
        db.commit()
        flash("Observação registrada no prontuário.", "success")
    else:
        flash("Digite a observação antes de salvar.", "error")
    db.close()
    return redirect(url_for("pacientes_editar", paciente_id=paciente_id))


@app.route("/receitas/<int:receita_id>")
@receita_required
def receita_ver(receita_id):
    db = get_db()
    receita = _receita_completa(db, receita_id)
    if receita is None:
        db.close()
        abort(404)
    if not paciente_acessivel(db, receita["paciente_id"]):
        db.close()
        flash("Receita de paciente não vinculado a você.", "error")
        return redirect(url_for("pacientes_lista"))
    db.close()
    # número de whatsapp do paciente (só dígitos, com DDI Brasil quando faltar)
    zap = "".join(ch for ch in (receita["paciente_telefone"] or "") if ch.isdigit())
    if zap and len(zap) <= 11:
        zap = "55" + zap
    return render_template(
        "receita_ver.html", r=receita, zap=zap, qr=_qr_data_uri(receita),
        clinica_nome=CLINICA_NOME, clinica_info=CLINICA_INFO,
    )


@app.route("/receitas/<int:receita_id>/pdf")
@receita_required
def receita_pdf(receita_id):
    db = get_db()
    receita = _receita_completa(db, receita_id)
    if receita is None:
        db.close()
        abort(404)
    if not paciente_acessivel(db, receita["paciente_id"]):
        db.close()
        abort(403)
    db.close()
    pdf_bytes = _gerar_pdf_receita(receita)
    from flask import Response
    nome = f"receita_{receita['paciente_nome'].split(' ')[0]}_{receita['data']}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"inline; filename={secure_filename(nome)}",
            # nunca guardar em cache: sempre mostrar o PDF atualizado
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.route("/receitas/<int:receita_id>/excluir", methods=["POST"])
@receita_required
def receita_excluir(receita_id):
    # Receitas fazem parte do histórico permanente do paciente e não são excluídas.
    db = get_db()
    receita = db.execute("SELECT * FROM receitas WHERE id = ?", (receita_id,)).fetchone()
    db.close()
    if receita is None:
        abort(404)
    flash("As receitas ficam armazenadas no histórico permanente e não podem ser excluídas.", "error")
    return redirect(url_for("pacientes_editar", paciente_id=receita["paciente_id"]))


@app.route("/pacientes/<int:paciente_id>/imprimir", methods=["POST"])
@receita_required
def imprimir_documentos(paciente_id):
    db = get_db()
    if not paciente_acessivel(db, paciente_id):
        db.close()
        abort(403)
    receita_ids = [i for i in request.form.getlist("receita_ids") if i.isdigit()]
    evolucao_ids = [i for i in request.form.getlist("evolucao_ids") if i.isdigit()]

    receitas = []
    for rid in receita_ids:
        row = _receita_completa(db, int(rid))
        if row and row["paciente_id"] == paciente_id:
            receitas.append(row)

    evolucoes = []
    if evolucao_ids:
        ph = ",".join("?" * len(evolucao_ids))
        evolucoes = db.execute(
            f"""SELECT e.*, p.nome AS paciente_nome, p.cpf AS paciente_cpf,
                       m.nome AS medico_nome, m.crm AS medico_crm, m.especialidade AS medico_especialidade
                FROM evolucoes e
                JOIN pacientes p ON p.id = e.paciente_id
                LEFT JOIN medicos m ON m.id = e.medico_id
                WHERE e.paciente_id = ? AND e.id IN ({ph})
                ORDER BY e.criado_em""",
            [paciente_id] + [int(i) for i in evolucao_ids],
        ).fetchall()
    db.close()

    if not receitas and not evolucoes:
        flash("Selecione ao menos um documento para imprimir.", "error")
        return redirect(url_for("pacientes_editar", paciente_id=paciente_id))

    from flask import Response
    pdf = _gerar_pdf_documentos(receitas, evolucoes)
    return Response(pdf, mimetype="application/pdf",
                    headers={"Content-Disposition": "inline; filename=documentos.pdf"})


def _logo_drawing(size=46):
    from reportlab.graphics.shapes import Drawing, Rect, Circle, PolyLine
    from reportlab.lib.colors import HexColor, white
    s = size / 64.0
    d = Drawing(size, size)
    badge = Rect(2 * s, 2 * s, 60 * s, 60 * s, rx=16 * s, ry=16 * s)
    badge.fillColor = HexColor("#0B5FA5"); badge.strokeColor = None
    d.add(badge)
    head = Circle(32 * s, 34 * s, 15 * s); head.fillColor = white; head.strokeColor = None
    d.add(head)
    pts = [17, 33, 26, 33, 29, 41, 34, 25, 37, 33, 47, 33]
    pulse = PolyLine([v * s for v in pts])
    pulse.strokeColor = HexColor("#1571C9"); pulse.strokeWidth = 2.6 * s
    pulse.strokeLineCap = 1; pulse.strokeLineJoin = 1
    d.add(pulse)
    dot = Circle(47 * s, 49 * s, 3 * s); dot.fillColor = HexColor("#7CC6FF"); dot.strokeColor = None
    d.add(dot)
    return d


def _cabecalho_pdf():
    from reportlab.platypus import Table, TableStyle, Paragraph, Image as RLImage
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    styles = getSampleStyleSheet()
    info_st = ParagraphStyle("cabinfo", parent=styles["Normal"], fontSize=9,
                             textColor=colors.HexColor("#6b7a77"), leading=12)
    # logo oficial (azul) — 200x60 px -> mantém proporção
    if LOGO_AZUL.exists():
        logo = RLImage(str(LOGO_AZUL), width=58 * mm, height=17.4 * mm)
    else:
        logo = _logo_drawing(46)
    t = Table([[logo], [Paragraph(CLINICA_INFO, info_st)]])
    t.hAlign = "LEFT"
    t.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (0, 0), 4),
        ("BOTTOMPADDING", (0, 1), (0, 1), 0),
    ]))
    return t


def _doc_pdf(buf):
    from reportlab.lib.units import mm, cm
    from reportlab.platypus import SimpleDocTemplate
    # Folha da receita: 16 cm de largura x 20 cm de altura
    return SimpleDocTemplate(
        buf, pagesize=(16 * cm, 20 * cm),
        leftMargin=24 * mm, rightMargin=12 * mm, topMargin=8 * mm, bottomMargin=8 * mm,
    )


def _flowables_controlada(r, rotulo):
    """Monta UMA via da Receita de Controle Especial (Portaria 344/98)."""
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, Image as RLImage
    from reportlab.lib.units import mm
    from reportlab.lib import colors

    AZ = colors.HexColor("#0B5FA5")
    PRETO = colors.HexColor("#222222")
    styles = getSampleStyleSheet()
    st_titulo = ParagraphStyle("ct", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=12, textColor=AZ, alignment=1, leading=14)
    st_emitlbl = ParagraphStyle("cel", parent=styles["Normal"], fontSize=7.5, textColor=PRETO, alignment=1, leading=9)
    st_contato = ParagraphStyle("cc", parent=styles["Normal"], fontSize=7.5, textColor=PRETO, alignment=0, leading=9.5)
    st_via = ParagraphStyle("cv", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8, textColor=colors.white, backColor=AZ, alignment=2, borderPadding=3)
    st_campo = ParagraphStyle("cf", parent=styles["Normal"], fontSize=10.5, textColor=PRETO, leading=19)
    st_presc = ParagraphStyle("cp", parent=styles["Normal"], fontSize=11, textColor=PRETO, leading=16)
    st_boxtit = ParagraphStyle("cbt", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8, textColor=AZ, alignment=1, leading=10)
    st_boxcampo = ParagraphStyle("cbc", parent=styles["Normal"], fontSize=8, textColor=PRETO, leading=15)
    st_assin = ParagraphStyle("ca", parent=styles["Normal"], fontSize=8, textColor=PRETO, alignment=1, leading=10)
    st_rodape = ParagraphStyle("cr", parent=styles["Normal"], fontSize=7, textColor=PRETO, alignment=1, leading=9)

    def P(txt, st):
        return Paragraph(str(txt).replace("\n", "<br/>"), st)

    bloco = [P(rotulo, st_via), Spacer(1, 1)]

    # ---- Caixa: Identificação do Emitente ----
    if LOGO_AZUL.exists():
        logo = RLImage(str(LOGO_AZUL), width=40 * mm, height=12 * mm)
    else:
        logo = P(CLINICA_NOME, st_contato)
    contato = P(
        "<b>Central de Atendimento:</b><br/>(11) 4412-2723 / 4412-2805<br/>"
        "Alameda Lindóia, 99 - Jardim do Lago<br/>CEP 12947-280 - Atibaia - SP<br/>"
        f"CNPJ {CLINICA_CNPJ}<br/>{CLINICA_SITE}", st_contato)
    inner = Table([[logo, contato]], colWidths=[64 * mm, None])
    inner.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    emit = Table([[P("RECEITUÁRIO CONTROLE ESPECIAL", st_titulo)],
                  [P("IDENTIFICAÇÃO DO EMITENTE", st_emitlbl)],
                  [inner]])
    emit.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 1, PRETO),
        ("LINEBELOW", (0, 1), (-1, 1), 0.5, PRETO),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    bloco += [emit, Spacer(1, 8)]

    # ---- Paciente / Endereço / CPF ----
    bloco.append(P(f"<b>Paciente:</b> {r['paciente_nome']}", st_campo))
    bloco.append(P(f"<b>Endereço:</b> {r['paciente_endereco'] or ''}", st_campo))
    bloco.append(P(f"<b>Prescrição — CPF:</b> {r['paciente_cpf']}", st_campo))
    bloco.append(Spacer(1, 8))

    # ---- Prescrição (medicamentos) + espaço para escrever ----
    if r["medicamentos"]:
        bloco.append(P(r["medicamentos"], st_presc))
    if r["instrucoes"]:
        bloco.append(Spacer(1, 6))
        bloco.append(P(r["instrucoes"], st_presc))
    bloco.append(Spacer(1, 18))

    # ---- Data + carimbo/assinatura do médico (espaço para carimbo) ----
    med_txt = ""
    if r["medico_nome"]:
        esp = f" — {r['medico_especialidade']}" if r["medico_especialidade"] else ""
        med_txt = f"{r['medico_nome']} — CRM {r['medico_crm'] or ''}{esp}"
    # 3 linhas em branco acima da linha = espaço para a médica carimbar e assinar
    assin = Table([[P(f"DATA: {r['data']}", st_boxcampo),
                    P(f"{med_txt}<br/><br/><br/><br/>_______________________________<br/>CARIMBO E ASSINATURA DO MÉDICO", st_assin)]],
                  colWidths=[46 * mm, None])
    assin.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
                               ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    bloco += [assin, Spacer(1, 14)]

    # ---- Quadros: Comprador / Fornecedor ----
    comprador = Table([[P("IDENTIFICAÇÃO DO COMPRADOR", st_boxtit)],
                       [P("Nome: ______________________________", st_boxcampo)],
                       [P("Ident.(RG): ____________ Órg.Emissor: ______", st_boxcampo)],
                       [P("End.: ______________________________", st_boxcampo)],
                       [P("Cidade/UF: _________________________", st_boxcampo)]])
    comprador.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.8, PRETO), ("LINEBELOW", (0, 0), (-1, 0), 0.5, PRETO),
                                   ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                                   ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    fornecedor = Table([[P("IDENTIFICAÇÃO DO FORNECEDOR", st_boxtit)],
                        [P("Carimbo do Estabelecimento", st_boxcampo)],
                        [P("", st_boxcampo)],
                        [P("Assinatura do Farmacêutico", st_boxcampo)],
                        [P("Data: ____/____/______", st_boxcampo)]],
                       rowHeights=[None, None, 16 * mm, None, None])
    fornecedor.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.8, PRETO), ("LINEBELOW", (0, 0), (-1, 0), 0.5, PRETO),
                                    ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                                    ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    rodape = Table([[comprador, fornecedor]], colWidths=[None, None])  # duas caixas do mesmo tamanho
    rodape.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("LEFTPADDING", (0, 0), (0, 0), 0), ("RIGHTPADDING", (0, 0), (0, 0), 4),
                                ("LEFTPADDING", (1, 0), (1, 0), 4), ("RIGHTPADDING", (1, 0), (1, 0), 0),
                                ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
    bloco += [rodape, Spacer(1, 2), P("1ª via - Retenção da Farmácia  /  2ª via - Orientação ao Paciente", st_rodape)]
    return bloco


def _flowables_receita(r):
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import Paragraph, Spacer, HRFlowable, PageBreak
    from reportlab.lib import colors

    styles = getSampleStyleSheet()
    h_clinica = ParagraphStyle("clinica", parent=styles["Title"], fontSize=16, textColor=colors.HexColor("#0B5FA5"), spaceAfter=2)
    h_info = ParagraphStyle("info", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#6b7a77"))
    h_sec = ParagraphStyle("sec", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#0B5FA5"), spaceBefore=10, spaceAfter=4)
    h_txt = ParagraphStyle("txt", parent=styles["Normal"], fontSize=11, leading=16)
    h_label = ParagraphStyle("label", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#333333"))
    h_via = ParagraphStyle("via", parent=styles["Normal"], fontSize=10, textColor=colors.white,
                           backColor=colors.HexColor("#0B5FA5"), alignment=2, spaceAfter=6, borderPadding=3)
    h_tarja = ParagraphStyle("tarja", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#c0392b"),
                             alignment=1, spaceAfter=8)
    h_ctrl = ParagraphStyle("ctrl", parent=styles["Normal"], fontSize=13, textColor=colors.HexColor("#0B5FA5"),
                            alignment=1, spaceBefore=4, spaceAfter=4, leading=16)
    h_emit_label = ParagraphStyle("emitlbl", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#333333"),
                                  alignment=1, spaceAfter=2)
    h_emit = ParagraphStyle("emit", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#333333"),
                            alignment=1, leading=12)

    def par(txt, style):
        return Paragraph(str(txt).replace("\n", "<br/>"), style)

    tipo_titulo = {
        "receita": "RECEITUÁRIO MÉDICO",
        "exame": "SOLICITAÇÃO DE EXAMES",
        "ambos": "RECEITA E SOLICITAÇÃO DE EXAMES",
        "controlada": "RECEITA DE CONTROLE ESPECIAL",
    }.get(r["tipo"], "RECEITUÁRIO MÉDICO")
    controlada = r["tipo"] == "controlada"

    def montar_via(rotulo):
        from reportlab.platypus import Image as RLImage
        from reportlab.lib.units import mm
        bloco = []
        if rotulo:
            bloco.append(par(rotulo, h_via))
        if controlada:
            # Cabeçalho no formato de Receituário de Controle Especial
            if LOGO_AZUL.exists():
                _logo = RLImage(str(LOGO_AZUL), width=44 * mm, height=13.2 * mm)
                _logo.hAlign = "CENTER"
                bloco.append(_logo)
            bloco.append(par("<b>RECEITUÁRIO CONTROLE ESPECIAL</b>", h_ctrl))
            bloco.append(HRFlowable(width="100%", thickness=1.2, color=colors.HexColor("#333333")))
            bloco.append(Spacer(1, 3))
            bloco.append(par("IDENTIFICAÇÃO DO EMITENTE", h_emit_label))
            bloco.append(par(f"<b>{CLINICA_NOME}</b>", h_emit))
            bloco.append(par(CLINICA_INFO, h_emit))
            if r["medico_nome"]:
                esp = f" — {r['medico_especialidade']}" if r["medico_especialidade"] else ""
                bloco.append(par(f"{r['medico_nome']} — CRM {r['medico_crm'] or ''}{esp}", h_emit))
            bloco.append(Spacer(1, 3))
            bloco.append(HRFlowable(width="100%", thickness=1.2, color=colors.HexColor("#333333")))
            bloco.append(Spacer(1, 10))
        else:
            # receita simples: só o logo no topo (endereço/atendimento vão no rodapé)
            if LOGO_AZUL.exists():
                _logo = RLImage(str(LOGO_AZUL), width=58 * mm, height=17.4 * mm)
                _logo.hAlign = "CENTER"
                bloco.append(_logo)
            bloco.append(Spacer(1, 6))
            bloco.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dde5e2")))
            bloco.append(Spacer(1, 8))
            bloco.append(par(f"<b>{tipo_titulo}</b>", h_sec))
        nasc = f" — Nasc.: {r['paciente_nasc']}" if r["paciente_nasc"] else ""
        bloco.append(par(f"<b>Paciente:</b> {r['paciente_nome']}{nasc}", h_label))
        bloco.append(par(f"<b>CPF:</b> {r['paciente_cpf']}", h_label))
        bloco.append(par(f"<b>Data:</b> {r['data']}", h_label))
        bloco.append(Spacer(1, 6))
        if r["medicamentos"]:
            bloco.append(par("Medicamentos", h_sec))
            bloco.append(par(r["medicamentos"], h_txt))
        if r["exames"]:
            bloco.append(par("Exames solicitados", h_sec))
            bloco.append(par(r["exames"], h_txt))
        if r["instrucoes"]:
            bloco.append(par("Orientações", h_sec))
            bloco.append(par(r["instrucoes"], h_txt))
        bloco.append(Spacer(1, 40))
        bloco.append(HRFlowable(width="60%", thickness=1, color=colors.HexColor("#333333")))
        # nome e CRM centralizados sob a linha de assinatura
        h_sign_nome = ParagraphStyle("signnome", parent=h_label, alignment=1)
        h_sign_crm = ParagraphStyle("signcrm", parent=h_info, alignment=1)
        if r["medico_nome"]:
            bloco.append(par(f"<b>{r['medico_nome']}</b>", h_sign_nome))
            crm = r["medico_crm"] or ""
            esp = r["medico_especialidade"] or ""
            bloco.append(par(f"CRM {crm} — {esp}", h_sign_crm))
        else:
            bloco.append(par("Assinatura / carimbo do médico", h_sign_crm))
        return bloco

    story = []
    if controlada:
        story += _flowables_controlada(r, "1ª VIA - FARMÁCIA")
        story.append(PageBreak())
        story += _flowables_controlada(r, "2ª VIA - PACIENTE")
    else:
        story += montar_via("")
    return story


def _flowables_evolucao(e):
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import Paragraph, Spacer, HRFlowable
    from reportlab.lib import colors

    styles = getSampleStyleSheet()
    h_sec = ParagraphStyle("esec", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#0B5FA5"), spaceBefore=10, spaceAfter=4)
    h_txt = ParagraphStyle("etxt", parent=styles["Normal"], fontSize=11, leading=16)
    h_label = ParagraphStyle("elabel", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#333333"))
    h_info = ParagraphStyle("einfo", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#6b7a77"))

    def par(txt, style):
        return Paragraph(str(txt).replace("\n", "<br/>"), style)

    bloco = [
        _cabecalho_pdf(),
        Spacer(1, 6), HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dde5e2")), Spacer(1, 8),
        par("<b>REGISTRO DE ATENDIMENTO / EVOLUÇÃO</b>", h_sec),
        par(f"<b>Paciente:</b> {e['paciente_nome']}", h_label),
        par(f"<b>CPF:</b> {e['paciente_cpf'] or '-'}", h_label),
        par(f"<b>Data:</b> {e['criado_em']}", h_label),
    ]
    if e["convenio"]:
        bloco.append(par(f"<b>Convênio:</b> {e['convenio']}", h_label))
    bloco.append(Spacer(1, 6))
    bloco.append(par(e["texto"], h_txt))
    bloco.append(Spacer(1, 40))
    bloco.append(HRFlowable(width="60%", thickness=1, color=colors.HexColor("#333333")))
    if e["medico_nome"]:
        bloco.append(par(f"<b>{e['medico_nome']}</b>", h_label))
        bloco.append(par(f"CRM {e['medico_crm'] or ''} — {e['medico_especialidade'] or ''}", h_info))
    else:
        bloco.append(par("Assinatura / carimbo do médico", h_info))
    return bloco


def _gerar_pdf_receita(r):
    from io import BytesIO
    from reportlab.lib.units import mm
    from reportlab.lib.utils import ImageReader
    buf = BytesIO()
    doc = _doc_pdf(buf)
    controlada = r["tipo"] == "controlada"
    qr_reader = ImageReader(BytesIO(_qr_png_bytes(_qr_texto_receita(r))))

    def onpage(c, d):
        _faixa_azul(c, d)
        if not controlada:
            _rodape_clinica(c, d)
        # QR Code com os dados da receita (preto, fácil de escanear)
        size = 28 * mm if not controlada else 17 * mm
        qx = d.pagesize[0] - size - 6 * mm
        # controlada: à direita dos dados do paciente (abaixo do quadro); simples: acima do rodapé
        qy = 131 * mm if controlada else 40 * mm
        c.drawImage(qr_reader, qx, qy, size, size, mask="auto")
        c.saveState()
        c.setFont("Helvetica", 6)
        c.setFillColorRGB(0.42, 0.48, 0.47)
        c.drawCentredString(qx + size / 2, qy - 7, "Escaneie para conferir")
        c.restoreState()

    doc.build(_flowables_receita(r), onFirstPage=onpage, onLaterPages=onpage)
    return buf.getvalue()


def _gerar_pdf_documentos(receitas, evolucoes):
    from io import BytesIO
    from reportlab.platypus import PageBreak
    buf = BytesIO()
    doc = _doc_pdf(buf)
    story = []
    primeiro = True
    for r in receitas:
        if not primeiro:
            story.append(PageBreak())
        story += _flowables_receita(r)
        primeiro = False
    for e in evolucoes:
        if not primeiro:
            story.append(PageBreak())
        story += _flowables_evolucao(e)
        primeiro = False
    doc.build(story, onFirstPage=_faixa_azul, onLaterPages=_faixa_azul)
    return buf.getvalue()


def _ler_form_paciente():
    return {
        "nome": request.form.get("nome", "").strip(),
        "cpf": request.form.get("cpf", "").strip(),
        "data_nascimento": request.form.get("data_nascimento", "").strip(),
        "telefone": request.form.get("telefone", "").strip(),
        "endereco": request.form.get("endereco", "").strip(),
        "historico": request.form.get("historico", "").strip(),
        "observacoes": request.form.get("observacoes", "").strip(),
    }


# ---------- Médicos ----------

@app.route("/medicos")
@login_required
def medicos_lista():
    db = get_db()
    rows = db.execute(
        """SELECT med.*,
                  (SELECT u.login FROM usuarios u
                   WHERE u.medico_id = med.id AND u.perfil = 'medico' AND u.ativo = 1
                   ORDER BY u.id LIMIT 1) AS user_login
           FROM medicos med ORDER BY med.nome"""
    ).fetchall()
    db.close()
    return render_template("medicos_lista.html", medicos=rows)


@app.route("/medicos/gerenciar", methods=["GET", "POST"])
@admin_required
def medicos_gerenciar():
    db = get_db()
    if request.method == "POST":
        ids = request.form.getlist("id")
        nomes = request.form.getlist("nome")
        crms = request.form.getlist("crm")
        esps = request.form.getlist("especialidade")
        tels = request.form.getlist("telefone")
        salas = request.form.getlist("sala")
        ativos = request.form.getlist("ativo")
        criados = atualizados = 0
        erros = []
        for i in range(len(nomes)):
            idv = (ids[i] if i < len(ids) else "").strip()
            nome = nomes[i].strip()
            crm = crms[i].strip()
            esp = esps[i].strip()
            tel = tels[i].strip()
            sala = salas[i].strip()
            ativo = 1 if (i < len(ativos) and ativos[i] == "1") else 0
            if idv:  # linha de médico existente
                if not nome or not crm:
                    erros.append(f"Linha {i + 1}: nome e CRM são obrigatórios.")
                    continue
                try:
                    db.execute(
                        "UPDATE medicos SET nome=?, crm=?, especialidade=?, telefone=?, sala=?, ativo=? WHERE id=?",
                        (nome, crm, esp, tel, sala, ativo, idv),
                    )
                    atualizados += 1
                except db.IntegrityError:
                    erros.append(f"CRM '{crm}' duplicado (linha {i + 1}).")
            else:  # linha nova
                if not nome and not crm and not esp:
                    continue  # linha em branco, ignora
                if not nome or not crm:
                    erros.append(f"Linha {i + 1}: preencha nome e CRM para cadastrar.")
                    continue
                try:
                    db.execute(
                        "INSERT INTO medicos (nome, crm, especialidade, telefone, sala, ativo) VALUES (?, ?, ?, ?, ?, ?)",
                        (nome, crm, esp, tel, sala, ativo),
                    )
                    criados += 1
                except db.IntegrityError:
                    erros.append(f"CRM '{crm}' duplicado (linha {i + 1}).")
        db.commit()
        db.close()
        for e in erros:
            flash(e, "error")
        flash(f"{atualizados} médico(s) atualizado(s) e {criados} cadastrado(s).", "success")
        return redirect(url_for("medicos_gerenciar"))
    medicos = db.execute("SELECT * FROM medicos ORDER BY nome").fetchall()
    db.close()
    return render_template("medicos_gerenciar.html", medicos=medicos)


@app.route("/medicos/novo", methods=["GET", "POST"])
@admin_required
def medicos_novo():
    if request.method == "POST":
        dados = _ler_form_medico()
        db = get_db()
        try:
            db.execute(
                "INSERT INTO medicos (nome, crm, especialidade, telefone, sala) VALUES (?, ?, ?, ?, ?)",
                (dados["nome"], dados["crm"], dados["especialidade"], dados["telefone"], dados["sala"]),
            )
            db.commit()
            flash("Médico cadastrado com sucesso.", "success")
            return redirect(url_for("medicos_lista"))
        except db.IntegrityError:
            flash("Já existe um médico com este CRM.", "error")
        finally:
            db.close()
    return render_template("medicos_form.html", medico=None)


@app.route("/medicos/<int:medico_id>/editar", methods=["GET", "POST"])
@admin_required
def medicos_editar(medico_id):
    db = get_db()
    medico = db.execute("SELECT * FROM medicos WHERE id = ?", (medico_id,)).fetchone()
    if medico is None:
        db.close()
        flash("Médico não encontrado.", "error")
        return redirect(url_for("medicos_lista"))
    if request.method == "POST":
        dados = _ler_form_medico()
        try:
            db.execute(
                "UPDATE medicos SET nome=?, crm=?, especialidade=?, telefone=?, sala=? WHERE id=?",
                (dados["nome"], dados["crm"], dados["especialidade"], dados["telefone"], dados["sala"], medico_id),
            )
            db.commit()
            flash("Dados do médico atualizados.", "success")
            return redirect(url_for("medicos_lista"))
        except db.IntegrityError:
            flash("Já existe um médico com este CRM.", "error")
        finally:
            db.close()
    else:
        db.close()
    return render_template("medicos_form.html", medico=medico)


@app.route("/medicos/<int:medico_id>/alternar-status", methods=["POST"])
@admin_required
def medicos_alternar_status(medico_id):
    db = get_db()
    db.execute("UPDATE medicos SET ativo = NOT ativo WHERE id = ?", (medico_id,))
    db.commit()
    db.close()
    return redirect(url_for("medicos_lista"))


@app.route("/medicos/<int:medico_id>/pacientes", methods=["GET", "POST"])
@admin_required
def medicos_pacientes(medico_id):
    """Tela do administrador para cadastrar quais pacientes são atendidos por este médico."""
    db = get_db()
    medico = db.execute("SELECT * FROM medicos WHERE id = ?", (medico_id,)).fetchone()
    if medico is None:
        db.close()
        flash("Médico não encontrado.", "error")
        return redirect(url_for("medicos_lista"))
    if request.method == "POST":
        paciente_ids = request.form.getlist("paciente_ids")
        db.execute("DELETE FROM medico_pacientes WHERE medico_id = ?", (medico_id,))
        for pid in paciente_ids:
            db.execute("INSERT OR IGNORE INTO medico_pacientes (medico_id, paciente_id) VALUES (?, ?)", (medico_id, pid))
        db.commit()
        db.close()
        flash(f"Pacientes do(a) {medico['nome']} atualizados ({len(paciente_ids)} vinculado(s)).", "success")
        return redirect(url_for("medicos_pacientes", medico_id=medico_id))
    pacientes = db.execute("SELECT * FROM pacientes ORDER BY nome").fetchall()
    vinculados = set(r["paciente_id"] for r in db.execute(
        "SELECT paciente_id FROM medico_pacientes WHERE medico_id = ?", (medico_id,)).fetchall())
    db.close()
    return render_template("medicos_pacientes.html", medico=medico, pacientes=pacientes, vinculados=vinculados)


def _ler_form_medico():
    return {
        "nome": request.form.get("nome", "").strip(),
        "crm": request.form.get("crm", "").strip(),
        "especialidade": request.form.get("especialidade", "").strip(),
        "telefone": request.form.get("telefone", "").strip(),
        "sala": request.form.get("sala", "").strip(),
    }


# ---------- Agenda / Consultas ----------

@app.route("/agenda")
@login_required
def agenda_lista():
    data_filtro = request.args.get("data", date.today().isoformat())
    status_filtro = request.args.get("status", "")
    db = get_db()
    query = """SELECT c.*, p.nome AS paciente_nome, m.nome AS medico_nome
               FROM consultas c
               JOIN pacientes p ON p.id = c.paciente_id
               JOIN medicos m ON m.id = c.medico_id
               WHERE c.data = ?"""
    params = [data_filtro]
    if status_filtro:
        query += " AND c.status = ?"
        params.append(status_filtro)
    if is_medico():
        query += " AND c.medico_id = ?"
        params.append(medico_id_atual() or -1)
    query += " ORDER BY c.hora"
    rows = db.execute(query, params).fetchall()
    db.close()
    return render_template("agenda_lista.html", consultas=rows, data_filtro=data_filtro, status_filtro=status_filtro)


@app.route("/agenda/nova", methods=["GET", "POST"])
@login_required
def agenda_nova():
    db = get_db()
    pacientes = db.execute("SELECT * FROM pacientes ORDER BY nome").fetchall()
    medicos = db.execute("SELECT * FROM medicos WHERE ativo = 1 ORDER BY nome").fetchall()
    if request.method == "POST":
        dados = _ler_form_consulta()
        db.execute(
            """INSERT INTO consultas (paciente_id, medico_id, data, hora, status, observacoes, tipo_atendimento, convenio)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (dados["paciente_id"], dados["medico_id"], dados["data"], dados["hora"], dados["status"], dados["observacoes"], dados["tipo_atendimento"], dados["convenio"]),
        )
        db.commit()
        db.close()
        flash("Consulta agendada com sucesso.", "success")
        return redirect(url_for("agenda_lista", data=dados["data"]))
    db.close()
    return render_template("agenda_form.html", consulta=None, pacientes=pacientes, medicos=medicos)


@app.route("/agenda/<int:consulta_id>/editar", methods=["GET", "POST"])
@login_required
def agenda_editar(consulta_id):
    db = get_db()
    consulta = db.execute("SELECT * FROM consultas WHERE id = ?", (consulta_id,)).fetchone()
    if consulta is None:
        db.close()
        flash("Consulta não encontrada.", "error")
        return redirect(url_for("agenda_lista"))
    pacientes = db.execute("SELECT * FROM pacientes ORDER BY nome").fetchall()
    medicos = db.execute("SELECT * FROM medicos WHERE ativo = 1 ORDER BY nome").fetchall()
    if request.method == "POST":
        dados = _ler_form_consulta()
        db.execute(
            """UPDATE consultas SET paciente_id=?, medico_id=?, data=?, hora=?, status=?, observacoes=?, tipo_atendimento=?, convenio=?
               WHERE id=?""",
            (dados["paciente_id"], dados["medico_id"], dados["data"], dados["hora"], dados["status"], dados["observacoes"], dados["tipo_atendimento"], dados["convenio"], consulta_id),
        )
        db.commit()
        db.close()
        flash("Consulta atualizada.", "success")
        return redirect(url_for("agenda_lista", data=dados["data"]))
    db.close()
    return render_template("agenda_form.html", consulta=consulta, pacientes=pacientes, medicos=medicos)


def _ler_form_consulta():
    return {
        "paciente_id": request.form.get("paciente_id"),
        "medico_id": request.form.get("medico_id"),
        "data": request.form.get("data", "").strip(),
        "hora": request.form.get("hora", "").strip(),
        "status": request.form.get("status", "agendada"),
        "observacoes": request.form.get("observacoes", "").strip(),
        "tipo_atendimento": request.form.get("tipo_atendimento", "particular"),
        "convenio": request.form.get("convenio", "").strip(),
    }


# ---------- Atendimento: Totem, Balcão e Telão ----------

def _fmt_senha(row):
    """Formata a senha para exibição: P015 (prioritária) ou N015 (normal)."""
    prefixo = "P" if row["prioridade"] else "N"
    return f"{prefixo}{row['numero']:03d}"


app.jinja_env.filters["senha"] = _fmt_senha


@app.route("/totem")
def totem():
    return render_template("totem.html")


@app.route("/totem/senha", methods=["POST"])
def totem_senha():
    prioridade = 1 if request.form.get("prioridade") == "1" else 0
    cpf = request.form.get("cpf", "").strip()
    hoje = date.today().isoformat()
    db = get_db()

    paciente_id = None
    consulta_id = None
    medico_id = None
    tipo_atend = None
    if cpf:
        pac = db.execute("SELECT * FROM pacientes WHERE cpf = ?", (cpf,)).fetchone()
        if pac:
            paciente_id = pac["id"]
            cons = db.execute(
                """SELECT * FROM consultas WHERE paciente_id = ? AND data = ?
                   AND status != 'cancelada' ORDER BY hora LIMIT 1""",
                (paciente_id, hoje),
            ).fetchone()
            if cons:
                consulta_id = cons["id"]
                medico_id = cons["medico_id"]
                tipo_atend = cons["tipo_atendimento"]

    ultimo = db.execute(
        "SELECT MAX(numero) AS m FROM senhas WHERE data = ?", (hoje,)
    ).fetchone()["m"]
    numero = (ultimo or 0) + 1
    cur = db.execute(
        """INSERT INTO senhas (numero, prioridade, data, paciente_id, consulta_id, medico_id, tipo_atendimento, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'aguardando')""",
        (numero, prioridade, hoje, paciente_id, consulta_id, medico_id, tipo_atend),
    )
    db.commit()
    senha_id = cur.lastrowid
    db.close()
    return redirect(url_for("totem_ticket", senha_id=senha_id))


@app.route("/totem/senha/<int:senha_id>")
def totem_ticket(senha_id):
    db = get_db()
    s = db.execute("SELECT * FROM senhas WHERE id = ?", (senha_id,)).fetchone()
    db.close()
    if s is None:
        abort(404)
    return render_template("totem_ticket.html", s=s)


@app.route("/balcao")
@login_required
def balcao():
    hoje = date.today().isoformat()
    db = get_db()
    aguardando = db.execute(
        """SELECT s.*, p.nome AS paciente_nome FROM senhas s
           LEFT JOIN pacientes p ON p.id = s.paciente_id
           WHERE s.data = ? AND s.status = 'aguardando'
           ORDER BY s.prioridade DESC, s.numero""",
        (hoje,),
    ).fetchall()
    em_atendimento = db.execute(
        """SELECT s.*, p.nome AS paciente_nome FROM senhas s
           LEFT JOIN pacientes p ON p.id = s.paciente_id
           WHERE s.data = ? AND s.status = 'atendimento'
           ORDER BY s.chamado_em""",
        (hoje,),
    ).fetchall()
    aguardando_medico = db.execute(
        """SELECT s.*, p.nome AS paciente_nome, m.nome AS medico_nome FROM senhas s
           LEFT JOIN pacientes p ON p.id = s.paciente_id
           LEFT JOIN medicos m ON m.id = s.medico_id
           WHERE s.data = ? AND s.status IN ('aguardando_medico','chamado')
           ORDER BY s.status DESC, s.chamado_em""",
        (hoje,),
    ).fetchall()
    db.close()
    return render_template(
        "balcao.html", aguardando=aguardando, em_atendimento=em_atendimento,
        aguardando_medico=aguardando_medico,
    )


@app.route("/balcao/chamar/<int:senha_id>", methods=["POST"])
@login_required
def balcao_chamar(senha_id):
    db = get_db()
    db.execute(
        "UPDATE senhas SET status='atendimento', chamado_em=datetime('now','localtime') WHERE id=?",
        (senha_id,),
    )
    db.commit()
    db.close()
    return redirect(url_for("balcao_atender", senha_id=senha_id))


@app.route("/balcao/atender/<int:senha_id>", methods=["GET", "POST"])
@login_required
def balcao_atender(senha_id):
    db = get_db()
    s = db.execute("SELECT * FROM senhas WHERE id = ?", (senha_id,)).fetchone()
    if s is None:
        db.close()
        abort(404)
    hoje = date.today().isoformat()
    pacientes = db.execute("SELECT * FROM pacientes ORDER BY nome").fetchall()
    medicos = db.execute("SELECT * FROM medicos WHERE ativo = 1 ORDER BY nome").fetchall()

    if request.method == "POST":
        paciente_id = request.form.get("paciente_id") or None
        medico_id = request.form.get("medico_id") or None
        consulta_id = request.form.get("consulta_id") or None
        tipo = request.form.get("tipo_atendimento", "particular")
        valor = request.form.get("valor", "").replace(",", ".").strip()
        valor = float(valor) if valor else None
        forma_pagamento = request.form.get("forma_pagamento", "").strip()
        convenio = request.form.get("convenio", "").strip()
        carteirinha = request.form.get("carteirinha", "").strip()
        autorizacao = request.form.get("autorizacao", "").strip()
        sala = ""
        if medico_id:
            m = db.execute("SELECT sala FROM medicos WHERE id = ?", (medico_id,)).fetchone()
            sala = (m["sala"] if m and m["sala"] else "") or ""
        acao = request.form.get("acao", "salvar")
        novo_status = "aguardando_medico" if acao == "encaminhar" else "atendimento"
        db.execute(
            """UPDATE senhas SET paciente_id=?, medico_id=?, consulta_id=?, tipo_atendimento=?,
               valor=?, forma_pagamento=?, convenio=?, carteirinha=?, autorizacao=?, sala=?,
               status=? WHERE id=?""",
            (paciente_id, medico_id, consulta_id, tipo, valor, forma_pagamento,
             convenio, carteirinha, autorizacao, sala, novo_status, senha_id),
        )
        db.commit()
        db.close()
        if acao == "encaminhar":
            flash("Atendimento registrado. Paciente encaminhado para a fila do médico.", "success")
            return redirect(url_for("balcao"))
        flash("Dados salvos. Imprima o recibo/autorização e depois encaminhe ao médico.", "success")
        return redirect(url_for("balcao_atender", senha_id=senha_id))

    # GET: monta contexto com dados do agendamento do dia
    consulta = None
    if s["consulta_id"]:
        consulta = db.execute(
            """SELECT c.*, m.nome AS medico_nome, m.sala AS medico_sala FROM consultas c
               LEFT JOIN medicos m ON m.id = c.medico_id WHERE c.id = ?""",
            (s["consulta_id"],),
        ).fetchone()
    consultas_hoje = []
    if s["paciente_id"] and not consulta:
        consultas_hoje = db.execute(
            """SELECT c.*, m.nome AS medico_nome FROM consultas c
               LEFT JOIN medicos m ON m.id = c.medico_id
               WHERE c.paciente_id = ? AND c.data = ? AND c.status != 'cancelada'
               ORDER BY c.hora""",
            (s["paciente_id"], hoje),
        ).fetchall()
    db.close()
    return render_template(
        "balcao_atender.html", s=s, consulta=consulta, consultas_hoje=consultas_hoje,
        pacientes=pacientes, medicos=medicos,
    )


@app.route("/balcao/chamar-medico/<int:senha_id>", methods=["POST"])
@login_required
def balcao_chamar_medico(senha_id):
    db = get_db()
    db.execute(
        "UPDATE senhas SET status='chamado', chamado_em=datetime('now','localtime') WHERE id=?",
        (senha_id,),
    )
    db.commit()
    db.close()
    return redirect(url_for("balcao"))


@app.route("/balcao/finalizar/<int:senha_id>", methods=["POST"])
@login_required
def balcao_finalizar(senha_id):
    db = get_db()
    db.execute("UPDATE senhas SET status='finalizado' WHERE id=?", (senha_id,))
    db.commit()
    db.close()
    return redirect(url_for("balcao"))


# ---------- Fila do médico (chamar o próximo no telão) ----------

def _medico_da_fila():
    """Qual médico está operando a fila: o médico logado, ou (admin) via ?medico=."""
    mid = medico_id_atual()
    if mid:
        return mid
    if g.user and g.user["perfil"] == "admin":
        val = request.values.get("medico", "").strip()
        return int(val) if val.isdigit() else None
    return None


@app.route("/minha-fila")
@login_required
def minha_fila():
    mid = _medico_da_fila()
    if not mid:
        flash("Entre como médico para ver a sua fila (menu Médicos → Entrar).", "error")
        return redirect(url_for("balcao"))
    hoje = date.today().isoformat()
    db = get_db()
    med = db.execute("SELECT * FROM medicos WHERE id = ?", (mid,)).fetchone()
    aguardando = db.execute(
        """SELECT s.*, p.nome AS paciente_nome FROM senhas s
           LEFT JOIN pacientes p ON p.id = s.paciente_id
           WHERE s.data=? AND s.medico_id=? AND s.status='aguardando_medico'
           ORDER BY s.prioridade DESC, s.numero""",
        (hoje, mid),
    ).fetchall()
    chamados = db.execute(
        """SELECT s.*, p.nome AS paciente_nome FROM senhas s
           LEFT JOIN pacientes p ON p.id = s.paciente_id
           WHERE s.data=? AND s.medico_id=? AND s.status='chamado'
           ORDER BY s.chamado_em DESC""",
        (hoje, mid),
    ).fetchall()
    minha_sala = (med["sala"] if med and med["sala"] else "") or ""
    db.close()
    return render_template("minha_fila.html", med=med, aguardando=aguardando,
                           chamados=chamados, minha_sala=minha_sala)


def _chamar_senha_telao(senha_id, sala):
    db = get_db()
    s = db.execute("SELECT * FROM senhas WHERE id=?", (senha_id,)).fetchone()
    if s is None:
        db.close()
        return None
    mid = medico_id_atual()
    if mid and s["medico_id"] != mid:  # médico só chama a própria fila
        db.close()
        return False
    db.execute(
        "UPDATE senhas SET status='chamado', sala=?, chamado_em=datetime('now','localtime') WHERE id=?",
        (sala, senha_id),
    )
    db.commit()
    med_id = s["medico_id"]
    db.close()
    return med_id


@app.route("/minha-fila/chamar-proximo", methods=["POST"])
@login_required
def minha_fila_chamar_proximo():
    mid = _medico_da_fila()
    if not mid:
        abort(403)
    sala = request.form.get("sala", "").strip()
    hoje = date.today().isoformat()
    db = get_db()
    prox = db.execute(
        """SELECT id FROM senhas WHERE data=? AND medico_id=? AND status='aguardando_medico'
           ORDER BY prioridade DESC, numero LIMIT 1""",
        (hoje, mid),
    ).fetchone()
    db.close()
    if prox:
        _chamar_senha_telao(prox["id"], sala)
        flash("📢 Próximo paciente chamado no telão.", "success")
    else:
        flash("Não há paciente aguardando na sua fila.", "error")
    return redirect(url_for("minha_fila", medico=mid if is_admin_user() else None))


@app.route("/minha-fila/chamar/<int:senha_id>", methods=["POST"])
@login_required
def minha_fila_chamar(senha_id):
    sala = request.form.get("sala", "").strip()
    res = _chamar_senha_telao(senha_id, sala)
    if res is None:
        abort(404)
    if res is False:
        flash("Essa senha não é da sua fila.", "error")
    else:
        flash("📢 Paciente chamado no telão.", "success")
    return redirect(url_for("minha_fila", medico=res if (res and is_admin_user()) else None))


@app.route("/minha-fila/finalizar/<int:senha_id>", methods=["POST"])
@login_required
def minha_fila_finalizar(senha_id):
    db = get_db()
    s = db.execute("SELECT medico_id FROM senhas WHERE id=?", (senha_id,)).fetchone()
    db.execute("UPDATE senhas SET status='finalizado' WHERE id=?", (senha_id,))
    db.commit()
    med_id = s["medico_id"] if s else None
    db.close()
    flash("Consulta finalizada.", "success")
    return redirect(url_for("minha_fila", medico=med_id if is_admin_user() else None))


@app.route("/atendimento/medico/<int:senha_id>", methods=["GET", "POST"])
@login_required
def atendimento_medico(senha_id):
    db = get_db()
    s = db.execute(
        """SELECT s.*, p.nome AS paciente_nome, p.cpf AS paciente_cpf,
                  m.nome AS medico_nome, m.especialidade AS medico_especialidade
           FROM senhas s
           LEFT JOIN pacientes p ON p.id = s.paciente_id
           LEFT JOIN medicos m ON m.id = s.medico_id
           WHERE s.id = ?""",
        (senha_id,),
    ).fetchone()
    if s is None:
        db.close()
        abort(404)
    if s["paciente_id"] is None:
        db.close()
        flash("Esta senha não tem paciente identificado. Identifique no balcão primeiro.", "error")
        return redirect(url_for("balcao"))
    if not paciente_acessivel(db, s["paciente_id"]):
        db.close()
        flash("Este paciente não está vinculado a você.", "error")
        return redirect(url_for("balcao"))

    if request.method == "POST":
        texto = request.form.get("texto", "").strip()
        if texto:
            db.execute(
                """INSERT INTO evolucoes (paciente_id, medico_id, consulta_id, convenio, texto)
                   VALUES (?, ?, ?, ?, ?)""",
                (s["paciente_id"], s["medico_id"], s["consulta_id"], s["convenio"], texto),
            )
            db.commit()
            flash("Observação do atendimento registrada.", "success")
        else:
            flash("Digite a observação antes de salvar.", "error")
        db.close()
        return redirect(url_for("atendimento_medico", senha_id=senha_id))

    evolucoes = db.execute(
        """SELECT e.*, m.nome AS medico_nome FROM evolucoes e
           LEFT JOIN medicos m ON m.id = e.medico_id
           WHERE e.paciente_id = ? ORDER BY e.criado_em DESC""",
        (s["paciente_id"],),
    ).fetchall()
    receitas = db.execute(
        """SELECT r.*, m.nome AS medico_nome FROM receitas r
           LEFT JOIN medicos m ON m.id = r.medico_id
           WHERE r.paciente_id = ? ORDER BY r.criado_em DESC""",
        (s["paciente_id"],),
    ).fetchall()
    db.close()
    return render_template("atendimento_medico.html", s=s, evolucoes=evolucoes, receitas=receitas)


@app.route("/senhas/<int:senha_id>/recibo")
@login_required
def senha_recibo(senha_id):
    dados = _senha_completa(senha_id)
    if dados is None:
        abort(404)
    from flask import Response
    pdf = _gerar_pdf_recibo(dados)
    return Response(pdf, mimetype="application/pdf",
                    headers={"Content-Disposition": "inline; filename=recibo.pdf"})


@app.route("/senhas/<int:senha_id>/autorizacao")
@login_required
def senha_autorizacao(senha_id):
    dados = _senha_completa(senha_id)
    if dados is None:
        abort(404)
    from flask import Response
    pdf = _gerar_pdf_autorizacao(dados)
    return Response(pdf, mimetype="application/pdf",
                    headers={"Content-Disposition": "inline; filename=autorizacao.pdf"})


def _senha_completa(senha_id):
    db = get_db()
    s = db.execute(
        """SELECT s.*, p.nome AS paciente_nome, p.cpf AS paciente_cpf,
                  m.nome AS medico_nome, m.crm AS medico_crm, m.especialidade AS medico_especialidade
           FROM senhas s
           LEFT JOIN pacientes p ON p.id = s.paciente_id
           LEFT JOIN medicos m ON m.id = s.medico_id
           WHERE s.id = ?""",
        (senha_id,),
    ).fetchone()
    db.close()
    return s


@app.route("/telao")
def telao():
    return render_template("telao.html")


@app.route("/telao/dados")
def telao_dados():
    from flask import jsonify
    hoje = date.today().isoformat()
    db = get_db()
    chamados = db.execute(
        """SELECT s.*, p.nome AS paciente_nome, m.nome AS medico_nome FROM senhas s
           LEFT JOIN pacientes p ON p.id = s.paciente_id
           LEFT JOIN medicos m ON m.id = s.medico_id
           WHERE s.data = ? AND s.status IN ('atendimento','chamado')
           ORDER BY s.chamado_em DESC LIMIT 8""",
        (hoje,),
    ).fetchall()
    db.close()
    def label(row):
        nome = (row["paciente_nome"] or "").split(" ")[0] if row["paciente_nome"] else ""
        if row["status"] == "atendimento":
            destino = "BALCÃO"
        else:
            destino = f"SALA {row['sala']}" if row["sala"] else (row["medico_nome"] or "CONSULTÓRIO")
        return {
            "senha": _fmt_senha(row),
            "nome": nome,
            "destino": destino,
            "medico": row["medico_nome"] or "",
            "tipo": row["status"],
        }
    dados = [label(r) for r in chamados]
    atual = dados[0] if dados else None
    return jsonify({"atual": atual, "recentes": dados[1:]})


def _gerar_pdf_recibo(s):
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
    from reportlab.lib import colors

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=22 * mm, rightMargin=22 * mm,
                            topMargin=20 * mm, bottomMargin=20 * mm)
    styles = getSampleStyleSheet()
    h_clinica = ParagraphStyle("c", parent=styles["Title"], fontSize=16, textColor=colors.HexColor("#0B5FA5"), spaceAfter=2)
    h_info = ParagraphStyle("i", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#6b7a77"))
    h_tit = ParagraphStyle("t", parent=styles["Heading2"], fontSize=14, textColor=colors.HexColor("#0B5FA5"), spaceBefore=14, spaceAfter=8)
    h_txt = ParagraphStyle("x", parent=styles["Normal"], fontSize=11, leading=18)
    valor = s["valor"] or 0
    story = [
        _cabecalho_pdf(),
        Spacer(1, 6), HRFlowable(width="100%", color=colors.HexColor("#dde5e2")), Spacer(1, 4),
        Paragraph("RECIBO DE PAGAMENTO", h_tit),
        Paragraph(f"Recebemos de <b>{s['paciente_nome'] or '-'}</b>"
                  f"{(' (CPF ' + s['paciente_cpf'] + ')') if s['paciente_cpf'] else ''} "
                  f"a importância de <b>R$ {valor:,.2f}</b>, referente a consulta médica particular"
                  f"{(' com ' + s['medico_nome']) if s['medico_nome'] else ''}"
                  f"{(' — ' + s['medico_especialidade']) if s['medico_especialidade'] else ''}.", h_txt),
        Spacer(1, 6),
        Paragraph(f"Forma de pagamento: {s['forma_pagamento'] or '-'}", h_txt),
        Paragraph(f"Data: {s['data']}", h_txt),
        Spacer(1, 50),
        HRFlowable(width="55%", color=colors.HexColor("#333333")),
        Paragraph(CLINICA_NOME, h_info),
    ]
    doc.build(story, onFirstPage=_faixa_azul, onLaterPages=_faixa_azul)
    return buf.getvalue()


def _gerar_pdf_autorizacao(s):
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
    from reportlab.lib import colors

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=22 * mm, rightMargin=22 * mm,
                            topMargin=20 * mm, bottomMargin=20 * mm)
    styles = getSampleStyleSheet()
    h_clinica = ParagraphStyle("c", parent=styles["Title"], fontSize=16, textColor=colors.HexColor("#0B5FA5"), spaceAfter=2)
    h_info = ParagraphStyle("i", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#6b7a77"))
    h_tit = ParagraphStyle("t", parent=styles["Heading2"], fontSize=14, textColor=colors.HexColor("#0B5FA5"), spaceBefore=14, spaceAfter=8)
    h_lbl = ParagraphStyle("l", parent=styles["Normal"], fontSize=11, leading=20)
    story = [
        _cabecalho_pdf(),
        Spacer(1, 6), HRFlowable(width="100%", color=colors.HexColor("#dde5e2")), Spacer(1, 4),
        Paragraph("AUTORIZAÇÃO DE ATENDIMENTO — CONVÊNIO", h_tit),
        Paragraph(f"<b>Paciente:</b> {s['paciente_nome'] or '-'}", h_lbl),
        Paragraph(f"<b>CPF:</b> {s['paciente_cpf'] or '-'}", h_lbl),
        Paragraph(f"<b>Convênio:</b> {s['convenio'] or '-'}", h_lbl),
        Paragraph(f"<b>Carteirinha:</b> {s['carteirinha'] or '-'}", h_lbl),
        Paragraph(f"<b>Nº de autorização:</b> {s['autorizacao'] or '-'}", h_lbl),
        Paragraph(f"<b>Médico:</b> {s['medico_nome'] or '-'}"
                  f"{(' — ' + s['medico_especialidade']) if s['medico_especialidade'] else ''}", h_lbl),
        Paragraph(f"<b>Data:</b> {s['data']}", h_lbl),
        Spacer(1, 60),
        HRFlowable(width="60%", color=colors.HexColor("#333333")),
        Paragraph("Assinatura do paciente", h_info),
    ]
    doc.build(story, onFirstPage=_faixa_azul, onLaterPages=_faixa_azul)
    return buf.getvalue()


# ---------- Usuários (admin) ----------

@app.route("/usuarios")
@admin_required
def usuarios_lista():
    db = get_db()
    rows = db.execute("SELECT * FROM usuarios ORDER BY nome").fetchall()
    db.close()
    return render_template("usuarios_lista.html", usuarios=rows)


@app.route("/usuarios/novo", methods=["GET", "POST"])
@admin_required
def usuarios_novo():
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        login_ = request.form.get("login", "").strip()
        senha = request.form.get("senha", "")
        perfil = request.form.get("perfil", "recepcao")
        medico_id = request.form.get("medico_id") or None
        if perfil != "medico":
            medico_id = None
        if len(senha) < 6:
            flash("A senha deve ter ao menos 6 caracteres.", "error")
        elif perfil == "medico" and not medico_id:
            flash("Para perfil Médico, selecione qual médico é este usuário.", "error")
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO usuarios (nome, login, senha_hash, perfil, medico_id) VALUES (?, ?, ?, ?, ?)",
                    (nome, login_, generate_password_hash(senha), perfil, medico_id),
                )
                db.commit()
                flash("Usuário criado com sucesso.", "success")
                return redirect(url_for("usuarios_lista"))
            except db.IntegrityError:
                flash("Já existe um usuário com este login.", "error")
            finally:
                db.close()
    db = get_db()
    medicos = db.execute("SELECT * FROM medicos WHERE ativo = 1 ORDER BY nome").fetchall()
    db.close()
    return render_template("usuarios_form.html", medicos=medicos)


@app.route("/backup", methods=["POST"])
@admin_required
def backup_agora():
    nome = fazer_backup()
    if nome:
        flash(f"Backup criado com sucesso: {nome} (na pasta 'backups'). "
              "Copie a pasta 'backups' para um pendrive ou nuvem para guardar fora do computador.", "success")
    else:
        flash("Não foi possível criar o backup.", "error")
    return redirect(request.referrer or url_for("usuarios_lista"))


@app.route("/backup/baixar", methods=["POST"])
@admin_required
def backup_baixar():
    nome = fazer_backup()
    if not nome:
        flash("Não foi possível criar o backup.", "error")
        return redirect(request.referrer or url_for("usuarios_lista"))
    return send_from_directory(BACKUP_DIR, nome, as_attachment=True, download_name=nome)


@app.route("/usuarios/<int:usuario_id>/alternar-status", methods=["POST"])
@admin_required
def usuarios_alternar_status(usuario_id):
    if usuario_id == g.user["id"]:
        flash("Você não pode desativar seu próprio usuário.", "error")
        return redirect(url_for("usuarios_lista"))
    db = get_db()
    db.execute("UPDATE usuarios SET ativo = NOT ativo WHERE id = ?", (usuario_id,))
    db.commit()
    db.close()
    return redirect(url_for("usuarios_lista"))


if __name__ == "__main__":
    init_db()
    backup_diario()  # cópia de segurança diária do histórico
    # host 0.0.0.0 permite abrir também nos outros aparelhos da rede (totem, telão, balcão)
    app.run(host="0.0.0.0", port=3001, debug=True)

