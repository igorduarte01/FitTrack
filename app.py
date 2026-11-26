# ============================================================
# FitTrack - Login e Criar conta (Streamlit + SQLite)
# Rodar:  streamlit run app.py
# ============================================================
import base64
import hashlib
import html
import os
import re
import secrets
import sqlite3
import struct
import time
from datetime import date, datetime, timedelta
from pathlib import Path

from urllib.parse import quote

import resend
import streamlit as st
import streamlit.components.v1 as components

# ----------------------------- Configurações -----------------------------
DB_NAME = os.environ.get("FITTRACK_DB", "fittrack.db")
MIN_SENHA = 8
ITERACOES = 200_000
ESCALA = 1        # tamanho geral da página (1 = design)
HEADER_ESCALA = 1.4  # tamanho do avatar e dos textos "FitTrack" / "Jornada Fitness" (1 = design)
PERFIL_ESCALA = 1.45  # tamanho do quadro da tela "Registrar conta" (1 = design)
CARD_ESCALA = 1.4  # tamanho só do quadro de baixo (campos, botões, textos); 1 = design, tente 1.2 a 1.8
DASH_ESCALA = 1.5  # tamanho do dashboard (1 = design)
TELA_ESCALA = 1.3  # tamanho das telas "Tudo pronto" e "Vamos personalizar seus treinos" (1 = design)
MODO_DEV = True  # True: mostra o botão "🛠 DEV" para pular entre as telas. COLOQUE False ANTES DE LANÇAR O SITE.
MODO_DEMO = False  # False: o código de recuperação é enviado por email (Resend). True: mostra o código na tela (só para testes).


# =========================== BANCO / REGRAS ===========================
def conectar():
    con = sqlite3.connect(DB_NAME)
    con.row_factory = sqlite3.Row
    return con


def criar_tabelas():
    con = conectar()
    with con:
        con.execute("""CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            senha_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            criado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
        con.execute("""CREATE TABLE IF NOT EXISTS reset_senha (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            codigo_hash TEXT NOT NULL,
            expira_em TEXT NOT NULL,
            usado INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id))""")
        con.execute("""CREATE TABLE IF NOT EXISTS perfis (
            usuario_id INTEGER PRIMARY KEY,
            nome TEXT NOT NULL,
            nascimento TEXT NOT NULL,
            peso_kg REAL NOT NULL,
            altura_cm REAL NOT NULL,
            genero TEXT NOT NULL,
            atualizado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id))""")
        con.execute("""CREATE TABLE IF NOT EXISTS objetivos (
            usuario_id INTEGER PRIMARY KEY,
            objetivo TEXT NOT NULL,
            atualizado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id))""")
        con.execute("""CREATE TABLE IF NOT EXISTS treinos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            data TEXT NOT NULL,
            grupo TEXT NOT NULL,
            nome TEXT NOT NULL,
            minutos INTEGER NOT NULL,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id))""")
        con.execute("""CREATE TABLE IF NOT EXISTS pesos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            data TEXT NOT NULL,
            peso_kg REAL NOT NULL,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id))""")
        con.execute("""CREATE TABLE IF NOT EXISTS niveis (
            usuario_id INTEGER PRIMARY KEY,
            nivel TEXT NOT NULL,
            atualizado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id))""")
    con.close()


def gerar_hash(senha, salt_hex):
    return hashlib.pbkdf2_hmac("sha256", senha.encode(), bytes.fromhex(salt_hex), ITERACOES).hex()


def hash_codigo(c):
    return hashlib.sha256(c.encode()).hexdigest()


def email_valido(e):
    return re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", e) is not None


def validar_senha(s):
    if len(s) < MIN_SENHA:
        return f"A senha deve ter pelo menos {MIN_SENHA} caracteres."
    if not re.search(r"[A-Za-z]", s) or not re.search(r"\d", s):
        return "A senha deve conter letras e números."
    return None


def cadastrar(email, senha, confirmar):
    email = email.strip().lower()
    if not email_valido(email):
        return False, "Email inválido."
    erro = validar_senha(senha)
    if erro:
        return False, erro
    if senha != confirmar:
        return False, "As senhas não coincidem."
    salt = secrets.token_hex(16)
    con = conectar()
    try:
        with con:
            con.execute("INSERT INTO usuarios (email, senha_hash, salt) VALUES (?,?,?)",
                        (email, gerar_hash(senha, salt), salt))
        return True, "Conta criada com sucesso!"
    except sqlite3.IntegrityError:
        return False, "Este email já está cadastrado."
    finally:
        con.close()


def login(email, senha):
    email = email.strip().lower()
    con = conectar()
    u = con.execute("SELECT * FROM usuarios WHERE email=?", (email,)).fetchone()
    con.close()
    if u is None or not secrets.compare_digest(gerar_hash(senha, u["salt"]), u["senha_hash"]):
        return False, "Email ou senha incorretos."
    return True, u["email"]


def solicitar_reset(email):
    email = email.strip().lower()
    con = conectar()
    u = con.execute("SELECT id FROM usuarios WHERE email=?", (email,)).fetchone()
    codigo = None
    if u:
        codigo = f"{secrets.randbelow(10**6):06d}"
        expira = (datetime.now() + timedelta(minutes=15)).isoformat()
        with con:
            con.execute("INSERT INTO reset_senha (usuario_id, codigo_hash, expira_em) VALUES (?,?,?)",
                        (u["id"], hash_codigo(codigo), expira))
    con.close()
    return codigo


def redefinir_senha(email, codigo, nova, confirmar):
    email = email.strip().lower()
    erro = validar_senha(nova)
    if erro:
        return False, erro
    if nova != confirmar:
        return False, "As senhas não coincidem."
    con = conectar()
    try:
        u = con.execute("SELECT id FROM usuarios WHERE email=?", (email,)).fetchone()
        if not u:
            return False, "Código inválido ou expirado."
        r = con.execute("""SELECT id, expira_em FROM reset_senha
                           WHERE usuario_id=? AND codigo_hash=? AND usado=0
                           ORDER BY id DESC LIMIT 1""",
                        (u["id"], hash_codigo(codigo.strip()))).fetchone()
        if not r or datetime.fromisoformat(r["expira_em"]) < datetime.now():
            return False, "Código inválido ou expirado."
        salt = secrets.token_hex(16)
        with con:
            con.execute("UPDATE usuarios SET senha_hash=?, salt=? WHERE id=?",
                        (gerar_hash(nova, salt), salt, u["id"]))
            con.execute("UPDATE reset_senha SET usado=1 WHERE id=?", (r["id"],))
        return True, "Senha redefinida com sucesso! Faça login."
    finally:
        con.close()


GENEROS = ["Masculino", "Feminino", "Outro"]


def _numero(texto):
    try:
        return float(str(texto).strip().replace(",", "."))
    except ValueError:
        return None


def tem_perfil(email):
    con = conectar()
    r = con.execute("""SELECT 1 FROM perfis p JOIN usuarios u ON u.id = p.usuario_id
                       WHERE u.email = ?""", (email.strip().lower(),)).fetchone()
    con.close()
    return r is not None


def obter_nome(email):
    con = conectar()
    r = con.execute("""SELECT p.nome FROM perfis p JOIN usuarios u ON u.id = p.usuario_id
                       WHERE u.email = ?""", (email.strip().lower(),)).fetchone()
    con.close()
    return r["nome"] if r else None


def normalizar_nome(nome):
    """Primeira letra de cada palavra (depois de cada espaço) em maiúscula: 'igor duarte' -> 'Igor Duarte'."""
    return " ".join(palavra[:1].upper() + palavra[1:].lower() for palavra in (nome or "").split())


def salvar_perfil(email, nome, nascimento, peso, altura, genero):
    """Tela 'Registrar conta' -> botão Criar conta."""
    nome = normalizar_nome(nome)
    if len(nome) < 3 or len(nome) > 100 or len(nome.split()) < 2:
        return False, "Informe seu nome completo."
    try:
        bruto = (nascimento or "").strip()
        digitos = re.sub(r"\D", "", bruto)
        if len(digitos) == 8:
            bruto = f"{digitos[:2]}/{digitos[2:4]}/{digitos[4:]}"
        nasc = datetime.strptime(bruto, "%d/%m/%Y").date()
    except ValueError:
        return False, "Data de nascimento inválida. Use o formato dd/mm/aaaa."
    hoje = date.today()
    idade = hoje.year - nasc.year - ((hoje.month, hoje.day) < (nasc.month, nasc.day))
    if nasc > hoje or idade > 120:
        return False, "Data de nascimento inválida."
    peso_kg = _numero(peso)
    if peso_kg is None or not 20 <= peso_kg <= 500:
        return False, "Peso inválido. Informe em kg (entre 20 e 500)."
    altura_cm = _numero(altura)
    if altura_cm is None or not 50 <= altura_cm <= 260:
        return False, "Altura inválida. Informe em cm (entre 50 e 260)."
    if genero not in GENEROS:
        return False, "Selecione o gênero."

    con = conectar()
    try:
        u = con.execute("SELECT id FROM usuarios WHERE email=?", (email.strip().lower(),)).fetchone()
        if not u:
            return False, "Usuário não encontrado. Faça login novamente."
        with con:
            con.execute("""INSERT INTO perfis (usuario_id, nome, nascimento, peso_kg, altura_cm, genero)
                           VALUES (?,?,?,?,?,?)
                           ON CONFLICT(usuario_id) DO UPDATE SET
                             nome=excluded.nome, nascimento=excluded.nascimento,
                             peso_kg=excluded.peso_kg, altura_cm=excluded.altura_cm,
                             genero=excluded.genero, atualizado_em=CURRENT_TIMESTAMP""",
                        (u["id"], nome, nasc.isoformat(), peso_kg, altura_cm, genero))
        resultado = (True, "Perfil criado com sucesso!")
    finally:
        con.close()
    registrar_peso(email, peso_kg)  # primeiro ponto do gráfico "Evolução do peso"
    return resultado


OBJETIVOS = [("massa", "Ganhar massa muscular"), ("gordura", "Perder gordura"),
             ("peso", "Manter o peso"), ("condicionamento", "Melhorar condicionamento"),
             ("forca", "Ganhar força"), ("saude", "Melhorar saúde")]


def obter_perfil(email):
    con = conectar()
    r = con.execute("""SELECT p.nome, p.nascimento, p.peso_kg, p.altura_cm, p.genero
                       FROM perfis p JOIN usuarios u ON u.id = p.usuario_id
                       WHERE u.email = ?""", (email.strip().lower(),)).fetchone()
    con.close()
    return dict(r) if r else None


def salvar_objetivo(email, chave):
    rotulos = dict(OBJETIVOS)
    if chave not in rotulos:
        return False, "Escolha uma opção para continuar."
    con = conectar()
    try:
        u = con.execute("SELECT id FROM usuarios WHERE email=?", (email.strip().lower(),)).fetchone()
        if not u:
            return False, "Usuário não encontrado. Faça login novamente."
        with con:
            con.execute("""INSERT INTO objetivos (usuario_id, objetivo) VALUES (?, ?)
                           ON CONFLICT(usuario_id) DO UPDATE SET
                             objetivo=excluded.objetivo, atualizado_em=CURRENT_TIMESTAMP""",
                        (u["id"], rotulos[chave]))
        return True, "Objetivo salvo!"
    finally:
        con.close()


def obter_objetivo(email):
    con = conectar()
    r = con.execute("""SELECT o.objetivo FROM objetivos o JOIN usuarios u ON u.id = o.usuario_id
                       WHERE u.email = ?""", (email.strip().lower(),)).fetchone()
    con.close()
    return r["objetivo"] if r else None


def tem_objetivo(email):
    return obter_objetivo(email) is not None


NIVEIS = [("iniciante", "Iniciante", "Estou começando agora ou tenho pouca experiência."),
          ("intermediario", "Intermediário", "Já treino há algum tempo e conheço os exercícios."),
          ("avancado", "Avançado", "Tenho bastante experiência e treino regularmente.")]


def salvar_nivel(email, chave):
    rotulos = {c: t for c, t, _ in NIVEIS}
    if chave not in rotulos:
        return False, "Escolha uma opção para continuar."
    con = conectar()
    try:
        u = con.execute("SELECT id FROM usuarios WHERE email=?", (email.strip().lower(),)).fetchone()
        if not u:
            return False, "Usuário não encontrado. Faça login novamente."
        with con:
            con.execute("""INSERT INTO niveis (usuario_id, nivel) VALUES (?, ?)
                           ON CONFLICT(usuario_id) DO UPDATE SET
                             nivel=excluded.nivel, atualizado_em=CURRENT_TIMESTAMP""",
                        (u["id"], rotulos[chave]))
        return True, "Nível salvo!"
    finally:
        con.close()


def obter_nivel(email):
    con = conectar()
    r = con.execute("""SELECT n.nivel FROM niveis n JOIN usuarios u ON u.id = n.usuario_id
                       WHERE u.email = ?""", (email.strip().lower(),)).fetchone()
    con.close()
    return r["nivel"] if r else None


def tem_nivel(email):
    return obter_nivel(email) is not None


GRUPOS_TREINO = {"peito": "Treino de peito", "costas": "Treino de costas", "bracos": "Treino de braços",
                 "ombros": "Treino de ombros", "pernas": "Treino de pernas"}


def _usuario_id(con, email):
    r = con.execute("SELECT id FROM usuarios WHERE email=?", (email.strip().lower(),)).fetchone()
    return r["id"] if r else None


def registrar_treino(email, grupo, minutos, data=None):
    """Registra um treino feito: alimenta 'Treinos realizados', 'Dias ativos' e 'Atividade recente' do dashboard."""
    if grupo not in GRUPOS_TREINO or not 1 <= int(minutos) <= 600:
        return False, "Treino inválido."
    con = conectar()
    try:
        uid = _usuario_id(con, email)
        if uid is None:
            return False, "Usuário não encontrado."
        with con:
            con.execute("INSERT INTO treinos (usuario_id, data, grupo, nome, minutos) VALUES (?,?,?,?,?)",
                        (uid, (data or date.today()).isoformat(), grupo, GRUPOS_TREINO[grupo], int(minutos)))
        return True, "Treino registrado!"
    finally:
        con.close()


def resumo_treinos(email):
    """(treinos realizados no total, dias ativos nos últimos 30 dias)."""
    con = conectar()
    try:
        uid = _usuario_id(con, email)
        if uid is None:
            return 0, 0
        total = con.execute("SELECT COUNT(*) FROM treinos WHERE usuario_id=?", (uid,)).fetchone()[0]
        desde = (date.today() - timedelta(days=29)).isoformat()
        dias = con.execute("SELECT COUNT(DISTINCT data) FROM treinos WHERE usuario_id=? AND data>=?",
                           (uid, desde)).fetchone()[0]
        return total, dias
    finally:
        con.close()


def atividades_recentes(email, limite=3):
    con = conectar()
    try:
        uid = _usuario_id(con, email)
        if uid is None:
            return []
        linhas = con.execute("""SELECT data, grupo, nome, minutos FROM treinos WHERE usuario_id=?
                                ORDER BY data DESC, id DESC LIMIT ?""", (uid, limite)).fetchall()
        return [dict(data=date.fromisoformat(r["data"]), grupo=r["grupo"], nome=r["nome"], minutos=r["minutos"])
                for r in linhas]
    finally:
        con.close()


def registrar_peso(email, kg, data=None):
    """Um peso por dia: registrar de novo no mesmo dia substitui o anterior."""
    dia = (data or date.today()).isoformat()
    con = conectar()
    try:
        uid = _usuario_id(con, email)
        if uid is None:
            return False
        with con:
            con.execute("DELETE FROM pesos WHERE usuario_id=? AND data=?", (uid, dia))
            con.execute("INSERT INTO pesos (usuario_id, data, peso_kg) VALUES (?,?,?)", (uid, dia, float(kg)))
        return True
    finally:
        con.close()


def historico_peso(email, dias=30):
    con = conectar()
    try:
        uid = _usuario_id(con, email)
        if uid is None:
            return []
        desde = (date.today() - timedelta(days=dias - 1)).isoformat()
        linhas = con.execute("SELECT data, peso_kg FROM pesos WHERE usuario_id=? AND data>=? ORDER BY data",
                             (uid, desde)).fetchall()
        return [(date.fromisoformat(r["data"]), r["peso_kg"]) for r in linhas]
    finally:
        con.close()


def peso_atual(email):
    con = conectar()
    try:
        uid = _usuario_id(con, email)
        r = con.execute("SELECT peso_kg FROM pesos WHERE usuario_id=? ORDER BY data DESC, id DESC LIMIT 1",
                        (uid,)).fetchone() if uid is not None else None
        return r["peso_kg"] if r else None
    finally:
        con.close()


EMAIL_DEV = "dev@fittrack.local"


def garantir_usuario_dev():
    """Modo desenvolvedor: cria (se precisar) um usuário de teste com perfil completo, para abrir qualquer tela
    sem preencher nada. A senha é aleatória e desconhecida, então ninguém consegue entrar com essa conta pelo login."""
    con = conectar()
    u = con.execute("SELECT id FROM usuarios WHERE email=?", (EMAIL_DEV,)).fetchone()
    if not u:
        salt = secrets.token_hex(16)
        with con:
            con.execute("INSERT INTO usuarios (email, senha_hash, salt) VALUES (?,?,?)",
                        (EMAIL_DEV, gerar_hash(secrets.token_urlsafe(24), salt), salt))
    con.close()
    if not tem_perfil(EMAIL_DEV):
        hoje = date.today()
        nasc = date(hoje.year - 15, hoje.month, min(hoje.day, 28))
        salvar_perfil(EMAIL_DEV, "Igor Duarte", nasc.strftime("%d/%m/%Y"), "58", "176", "Masculino")
    if not tem_objetivo(EMAIL_DEV):
        salvar_objetivo(EMAIL_DEV, "massa")
    if not tem_nivel(EMAIL_DEV):
        salvar_nivel(EMAIL_DEV, "intermediario")
    return EMAIL_DEV


def zerar_dados_dev():
    con = conectar()
    try:
        uid = _usuario_id(con, EMAIL_DEV)
        if uid is not None:
            with con:
                con.execute("DELETE FROM treinos WHERE usuario_id=?", (uid,))
                con.execute("DELETE FROM pesos WHERE usuario_id=?", (uid,))
    finally:
        con.close()
    if uid is not None:
        registrar_peso(EMAIL_DEV, 58)


def gerar_dados_exemplo_dev():
    """Modo desenvolvedor: cria treinos e pesos dos últimos 30 dias para o dashboard aparecer preenchido."""
    garantir_usuario_dev()
    zerar_dados_dev()
    hoje = date.today()
    treinos = [(0, "peito", 45), (1, "costas", 50), (3, "bracos", 35), (4, "pernas", 55), (6, "ombros", 40),
               (8, "peito", 45), (11, "costas", 50), (13, "bracos", 35), (16, "pernas", 55), (19, "ombros", 40),
               (23, "peito", 45), (27, "costas", 50)]
    for atras, grupo, minutos in treinos:
        registrar_treino(EMAIL_DEV, grupo, minutos, hoje - timedelta(days=atras))
    for atras, kg in ((29, 56.4), (24, 56.9), (19, 56.7), (14, 57.2), (9, 57.0), (4, 57.4), (0, 57.5)):
        registrar_peso(EMAIL_DEV, kg, hoje - timedelta(days=atras))


# =========================== INTERFACE (Streamlit) ===========================
st.set_page_config(page_title="FitTrack", page_icon="💪", layout="centered")
criar_tabelas()

LARGURAS = {"login": 620, "esqueceu": 620, "home": 620, "cadastro": 580, "perfil": 620}

# ----------------------------- ícones (PNG recortados das suas interfaces) -----------------------------
PASTA_ICONES = Path(__file__).parent / "assets" / "icones"
AMPLIACAO_ICONE = 2  # os PNGs foram salvos 2x maiores que no design (ficam nítidos com o zoom)
_CACHE_ICONE = {}


def _icone(nome):
    """(data URI, largura, altura em px do design) ou None se o arquivo não existir."""
    if nome not in _CACHE_ICONE:
        arq = PASTA_ICONES / f"{nome}.png"
        info = None
        if nome and arq.is_file():
            dados = arq.read_bytes()
            largura, altura = struct.unpack(">II", dados[16:24])
            info = ("data:image/png;base64," + base64.b64encode(dados).decode(),
                    largura / AMPLIACAO_ICONE, altura / AMPLIACAO_ICONE)
        _CACHE_ICONE[nome] = info
    return _CACHE_ICONE[nome]


def icone_dim(nome, padrao=(24, 24)):
    i = _icone(nome)
    return (i[1], i[2]) if i else padrao


def img_icone(nome, svg_reserva="", k=1.0):
    """<img> do ícone recortado do design (altura = altura do design x k). Sem o arquivo, usa o desenho de reserva."""
    i = _icone(nome)
    if not i:
        return svg_reserva
    return f'<img class="ic" alt="" src="{i[0]}" style="height:{i[2] * k:.1f}px">'


_VARS_ICONE = {}


def ref_icone(nome, svg_reserva=""):
    """Como url_icone, mas guarda a imagem uma única vez numa variável CSS (--ic-nome) e devolve var(--ic-nome)."""
    _VARS_ICONE[nome or "vazio"] = url_icone(nome, svg_reserva)
    return f"var(--ic-{nome or 'vazio'})"


def css_vars_icones():
    return ":root { " + " ".join(f"--ic-{n}:{u};" for n, u in _VARS_ICONE.items()) + " }"


def url_icone(nome, svg_reserva=""):
    """url(...) para background-image: o PNG recortado, ou o desenho de reserva."""
    i = _icone(nome)
    if i:
        return f'url("{i[0]}")'
    if svg_reserva:
        return 'url("data:image/svg+xml,' + quote(svg_reserva) + '")'
    return "none"


SVG_EMAIL = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#d1d5db' "
             "stroke-width='1.8' stroke-linejoin='round'><rect x='2' y='5' width='20' height='14' rx='2'/>"
             "<path d='M2.5 7l9.5 7 9.5-7'/></svg>")
SVG_LOCK = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path d='M7.5 11V7.5a4.5 4.5 0 019 0V11' "
            "fill='none' stroke='#d1d5db' stroke-width='2'/><rect x='4.5' y='10.5' width='15' height='11' "
            "rx='2.5' fill='#d1d5db'/></svg>")


SVG_PESSOA = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><circle cx='12' cy='8' r='4.2' fill='#d1d5db'/>"
              "<path d='M3.5 21c0-5.2 4.2-7.2 8.5-7.2s8.5 2 8.5 7.2z' fill='#d1d5db'/></svg>")
SVG_CALENDARIO = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#d1d5db' stroke-width='1.8' "
                  "stroke-linecap='round'><rect x='3' y='5' width='18' height='16' rx='2'/><path d='M3 10h18M8 3v4M16 3v4'/></svg>")
SVG_PESO = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#d1d5db' stroke-width='1.8' "
            "stroke-linejoin='round'><path d='M6 21h12l2.5-11h-17z'/><circle cx='12' cy='6' r='2.6'/></svg>")
SVG_ALTURA = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#d1d5db' stroke-width='1.8' "
              "stroke-linecap='round' stroke-linejoin='round'><path d='M12 3v18M8 7l4-4 4 4M8 17l4 4 4-4'/></svg>")


SVG_OLHO = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#d1d5db' stroke-width='1.8' "
            "stroke-linecap='round' stroke-linejoin='round'><path d='M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z'/>"
            "<circle cx='12' cy='12' r='3'/></svg>")


def _regras_campo(chave, nome, svg, fator, esq=9):
    """Ícone dentro do campo (à esquerda) e espaço para o texto não ficar em cima dele."""
    w, h = icone_dim(nome, (22, 22))
    return [f'.st-key-{chave} [data-testid="stTextInputRootElement"] {{ background-image:{ref_icone(nome, svg)} !important; '
            f'background-repeat:no-repeat; background-position:{esq}px center; background-size:auto {h * fator:.1f}px; }}',
            f'.st-key-{chave} input {{ padding-left:{esq + w * fator + 10:.0f}px !important; }}']


def _regras_olho(escopo, nome, fator):
    """Troca o ícone do olho do campo de senha pelo do design (só se o PNG existir)."""
    i = _icone(nome)
    if not i:
        return []
    w, h = icone_dim(nome)
    alvo = f'{escopo} [data-testid="stTextInputRootElement"]'
    return [f'{alvo} button {{ background-image:{ref_icone(nome)} !important; background-repeat:no-repeat; '
            f'background-position:center; background-size:auto {h * fator:.1f}px; min-width:{w * fator + 16:.0f}px; }}',
            f'{alvo} button * {{ opacity:0 !important; }}',
            f'{alvo}:has(input[type="text"]) button {{ background-image:{ref_icone("olho_aberto", SVG_OLHO)} !important; '
            f'background-size:auto {h * fator:.1f}px; }}']


def _regras_genero():
    """Botões de gênero: ícones do design (♂ ♀ pessoa) e a bolinha ao lado, que muda de cor ao escolher."""
    regras = []
    base = '.stApp [class*="st-key-gen_"] .stButton button[kind="tertiary"]'
    regras.append('[class*="st-key-gen_"] { display:flex; justify-content:center; align-items:center; width:100%; }')
    regras.append('[data-testid="stColumn"]:has([class*="st-key-gen_"]) { display:flex; justify-content:center; }')
    regras.append('.stApp [class*="st-key-gen_"] .stButton button { margin:0 auto; min-width:0; }')
    regras.append(f'{base} {{ gap:8px; width:auto !important; padding:0 6px; }}')
    regras.append('.stApp [class*="st-key-gen_"] .stButton { width:auto !important; }')
    regras.append('.stApp [class*="st-key-gen_"] .stButton button [data-testid="stMarkdownContainer"] '
                  '{ width:auto !important; flex:none !important; }')
    regras.append(f'{base} p {{ font-size:40px !important; font-weight:700 !important; line-height:1 !important; }}')
    regras.append(f'{base}::after {{ content:""; width:22px; height:22px; box-sizing:border-box; border-radius:50%; '
                  'background:#d9d9d9; border:3px solid #000; flex:none; }')
    for letra, cor in (("m", "#3b82f6"), ("f", "#ff5fa2"), ("o", "#4b5563")):  # azul, rosa, cinza escuro
        regras.append(f'.stApp .st-key-gen_on_{letra} .stButton button[kind="tertiary"]::after {{ background:{cor}; }}')
    for estado in ("on", "off"):
        topo = f'.stApp .st-key-gen_{estado}_'
        regras.append(f'{topo}m .stButton button[kind="tertiary"] p {{ color:#7b9cff !important; }}')
        regras.append(f'{topo}f .stButton button[kind="tertiary"] p {{ color:#ff5fa2 !important; }}')
        for letra, nome, svg in (("m", "macho", ""), ("f", "femea", ""), ("o", "outro", SVG_PESSOA)):
            if not svg and not _icone(nome):
                continue  # sem o PNG, ♂ e ♀ continuam como letras coloridas
            w, h = icone_dim(nome, (34, 34))
            p = f'{topo}{letra} .stButton button[kind="tertiary"] p'
            regras.append(f'{p} {{ font-size:0 !important; display:flex; flex-direction:column; align-items:center; gap:3px; }}')
            regras.append(f'{p}::before {{ content:""; display:inline-block; width:{w * 0.95:.1f}px; height:{h * 0.95:.1f}px; '
                          f'background:{ref_icone(nome, svg)} center/contain no-repeat; }}')
        regras.append(f'{topo}o .stButton button[kind="tertiary"] p::after {{ content:"Outro"; font-size:11px; '
                      'font-weight:400; color:#e5e7eb; line-height:1; }')
    return regras


def css_icones(tela):
    """Só gera os ícones da tela que está aberta (assim cada página carrega só o que usa)."""
    regras = []
    if tela in ("login", "cadastro"):
        f = 0.88
        for k in ("login_email", "cad_email"):
            regras += _regras_campo(k, "mail", SVG_EMAIL, f)
        for k in ("login_senha", "cad_senha", "cad_conf"):
            regras += _regras_campo(k, "lock", SVG_LOCK, f)
        regras += _regras_olho('[class*="st-key-card_"]', "eye", f)
    elif tela == "esqueceu":
        regras += _regras_campo("rec_email", "mail_escuro", SVG_EMAIL, 1.0)
        for k in ("rec_cod", "rec_nova", "rec_conf"):
            regras += _regras_campo(k, "lock_escuro", SVG_LOCK, 1.0)
        regras += _regras_olho(".st-key-painel_rec", "eye_escuro", 1.0)
    elif tela == "perfil":
        regras += _regras_campo("perf_nome", "pessoa_campo", SVG_PESSOA, 0.93)
        regras += _regras_campo("perf_nasc", "calendario_campo", SVG_CALENDARIO, 0.93)
        regras += _regras_campo("perf_peso", "peso_campo", SVG_PESO, 0.93)
        regras += _regras_campo("perf_altura", "altura_campo", SVG_ALTURA, 0.93)
        regras += _regras_genero()
    return "\n".join(regras)


CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&display=swap');
.stApp, .stApp *:not([data-testid="stIconMaterial"]) { font-family:'Space Grotesk',sans-serif; }
.stApp { background:#0b1220; overflow-x:hidden; }
[data-testid="stMain"], [data-testid="stAppViewContainer"] { overflow-x:hidden; }
[data-testid="stHorizontalBlock"], [data-testid="stColumn"], .st-key-painel_perfil,
.st-key-painel_perfil [data-testid="stMarkdown"], .st-key-painel_perfil [data-testid="stMarkdownContainer"] { overflow:visible !important; }
header[data-testid="stHeader"], #MainMenu, footer { display:none; }
.block-container { max-width:__LARGURA__; padding:8px 0; zoom:__ESCALA__; box-sizing:border-box; }
/* centraliza o conteúdo na vertical, em qualquer altura de janela */
.block-container > [data-testid="stVerticalBlock"] { min-height:calc(100vh - 16px); min-height:calc(100dvh - 16px); justify-content:center; }
.block-container [data-testid="stVerticalBlock"] { gap:0; }
.block-container [data-testid="stHorizontalBlock"] { gap:8px; }

/* textos */
.ft-avatar { display:flex; justify-content:center; margin-bottom:14px; zoom:__HEADER_ESCALA__; }
.ft-avatar svg { display:block; height:76px; width:76px; }
.ft-logo { display:flex; justify-content:center; align-items:center; gap:8px; font-size:26px; line-height:30px; margin:0 0 6px; zoom:__HEADER_ESCALA__; }
.ft-logo svg { height:22px; width:auto; }
.ft-logo i, .ft-logo b, .ft-logo-p i, .ft-logo-p b { font-style:italic; font-weight:700; }
.ft-logo i, .ft-logo-p i { color:#fff; } .ft-logo b, .ft-logo-p b { color:#2f8bff; }
.ft-icone-halter { display:flex; justify-content:center; margin:0 0 30px; zoom:__HEADER_ESCALA__; }
.ft-icone-halter svg { height:20px; width:auto; display:block; }
.ft-titulo { color:#fff; font-weight:700; font-size:27px; text-align:center; margin:0; line-height:34px; zoom:__HEADER_ESCALA__; }
.ft-sub { color:#e5e7eb; font-size:19px; text-align:center; margin:0 0 30px 0; line-height:26px; zoom:__HEADER_ESCALA__; }
.ft-msg { text-align:center; font-size:14px; padding:2px 0; }
.ft-erro { color:#fca5a5; } .ft-ok { color:#86efac; }
.ft-bemvindo { color:#fff; text-align:center; font-size:18px; padding:10px; }
[data-testid="stMarkdown"], [data-testid="stMarkdownContainer"], .stMarkdown { margin:0 !important; padding:0; }
[data-testid="stMarkdownContainer"] p { margin:0; }

/* cartão escuro */
.block-container [class*="st-key-card_"] { zoom:__CARD_ESCALA__; background:#2b3340; border-radius:14px; padding:12px 6px; gap:10px !important; }
.block-container [class*="st-key-card_"] [data-testid="stVerticalBlock"] { gap:10px; }

/* campos de texto e senha */
[class*="st-key-card_"] [data-testid="stTextInputRootElement"] {
    background-color:#5b616c !important; border:none !important; border-radius:8px !important;
    height:34px !important; min-height:34px !important; box-shadow:none !important; }
[class*="st-key-card_"] div[data-baseweb="input"],
[class*="st-key-card_"] div[data-baseweb="base-input"] { background:transparent !important; border:none !important; }
[class*="st-key-card_"] input { background:transparent !important; color:#fff !important; font-size:17px;
    height:34px; padding-top:0; padding-bottom:0; padding-left:12px; }
[class*="st-key-card_"] input::placeholder { color:#f3f4f6; opacity:1; }
[class*="st-key-card_"] [data-testid="stTextInputRootElement"] button { background:transparent !important; color:#d1d5db !important; }

/* botões: ocupam toda a largura da coluna */
[class*="st-key-btn_"], [class*="st-key-btn_"] .stButton { width:100% !important; }
[class*="st-key-btn_"] button { width:100% !important; }
.stButton button[kind="primary"], .stButton button[data-testid="stBaseButton-primary"] {
    background:#2563eb; color:#fff; font-weight:700; font-size:17px; border:none;
    border-radius:6px; min-height:34px; height:34px; padding:0; }
.stButton button[kind="primary"]:hover { background:#1d4ed8; color:#fff; }
.stButton button[kind="tertiary"], .stButton button[data-testid="stBaseButton-tertiary"] {
    background:transparent;
    color:#e5e7eb;
    border:none;
    box-shadow:none;
    font-size:16px;
    min-height:34px;
    width:100%;
    justify-content:center;
    padding:0;
}
.stButton button[kind="tertiary"]:hover { color:#fff; background:transparent; }
.stButton button[kind="primary"] p, .stButton button[data-testid="stBaseButton-primary"] p {
    color:#fff !important; font-weight:700 !important; font-size:17px !important; line-height:1; }
.stButton button[kind="tertiary"] p, .stButton button[data-testid="stBaseButton-tertiary"] p {
    color:#e5e7eb !important; font-weight:400 !important; font-size:16px !important; line-height:1; }
.st-key-btn_esq button { justify-content:flex-end !important; }

/* tela Registrar conta */
.st-key-js_mask { height:0; overflow:hidden; margin:0; padding:0; }
.block-container .st-key-card_perfil { zoom:__PERFIL_ESCALA__; }
/* centraliza o quadro na vertical em relação à coluna da direita (avatar + foto) */
[data-testid="stHorizontalBlock"]:has(.st-key-card_perfil) { align-items:center !important; }
.ft-titulo-card { color:#fff; font-weight:700; font-size:26px; text-align:center; line-height:34px; margin:0; }
.ft-genero { color:#e5e7eb; font-size:17px; text-align:center; line-height:22px; margin-top:4px; }
.st-key-painel_perfil .ft-sub { margin-bottom:10px; }
.st-key-painel_perfil .ft-titulo, .st-key-painel_perfil .ft-sub, .st-key-painel_perfil .ft-avatar, .st-key-painel_perfil .ft-logo { position:relative; z-index:2; }
.st-key-painel_perfil [data-testid="stImage"] { width:100% !important; }
.st-key-painel_perfil img { width:calc(100% + (100vw - min(1280px, 96vw)) / 2) !important; max-width:none !important;
    height:370px; margin-top:-30px; position:relative; z-index:0; object-fit:cover; display:block;
    /* degradê: a foto some suavemente no fundo escuro, em cima e embaixo */
    -webkit-mask-image:linear-gradient(to bottom, transparent 0%, #000 28%, #000 72%, transparent 100%);
            mask-image:linear-gradient(to bottom, transparent 0%, #000 28%, #000 72%, transparent 100%); }
.ft-foto { height:370px; margin-top:-30px; display:flex; align-items:center; justify-content:center;
           background:linear-gradient(160deg,#1b2433 0%,#0b1220 100%); }

/* ícones recortados do design */
.ic { display:inline-block; vertical-align:middle; flex:none; max-width:none; }

/* links com parte em azul: "Não tem uma conta? Criar conta" */
.stButton button[kind="tertiary"] p strong, .stButton button[data-testid="stBaseButton-tertiary"] p strong { color:#2563eb !important; font-weight:700 !important; }

/* animação de fade entre telas */
@keyframes ftfadein { from { opacity:0; } to { opacity:1; } }
@keyframes ftfadeout { from { opacity:1; } to { opacity:0; } }

/* telas 4 e 5: tamanho do design (711x441 e 709x444) ampliado pelo zoom */
.block-container .st-key-zoom_resumo, .block-container .st-key-zoom_obj { zoom:__TELA_ESCALA__; width:100%; box-sizing:border-box; }
.ft-logo-p { display:flex; align-items:center; gap:7px; font-size:22px; line-height:26px; }
.ft-logo-p svg { height:19px; width:auto; }

/* tela 4: Tudo pronto */
.st-key-zoom_resumo [data-testid="stHorizontalBlock"] { gap:17px; align-items:flex-start; }
.block-container .st-key-painel_resumo { background:#101b30; border-radius:14px; padding:20px 12px 16px 12px; }
.block-container .st-key-painel_info { gap:12px; padding-top:14px; }
.rs-hr { height:1px; background:#4a5568; margin:16px 6px 14px; }
.rs-avatar { display:flex; justify-content:center; margin:14px 0 10px; }
.rs-avatar svg { width:78px; height:78px; display:block; }
.rs-nome { color:#fff; font-size:22px; line-height:28px; text-align:center; margin:0 0 8px; word-break:break-word; }
.rs-titulo { color:#94a3b8; font-size:14px; letter-spacing:.6px; margin:14px 8px 10px; }
.rs-item { display:flex; align-items:center; gap:10px; margin:0 8px 14px; }
.rs-item > svg { width:16px; height:16px; flex:none; }
.rs-lbl { color:#9aa5b6; font-size:13px; line-height:16px; }
.rs-val { color:#fff; font-size:14px; line-height:17px; }
.rs-topo { display:flex; align-items:center; gap:10px; margin:8px 0 8px 15px; color:#fff; font-size:25px; font-weight:700; line-height:38px; }
.rs-topo svg { width:38px; height:38px; flex:none; }
.rs-sub { color:#fff; font-size:16px; line-height:22px; margin:0 0 14px; }
.rs-card { background:#172a4b; border-radius:14px; padding:16px 18px 10px; }
.rs-card-t { color:#fff; font-weight:700; font-size:17px; line-height:22px; }
.rs-card-s { color:#e2e8f0; font-size:11.5px; line-height:15px; margin:4px 0 16px; }
.rs-li { display:flex; align-items:center; gap:9px; margin:0 0 30px; color:#fff; font-weight:700; font-size:12.5px; }
.rs-li svg { width:20px; height:20px; flex:none; }

/* tela 5: objetivos */
.block-container .st-key-zoom_obj { gap:16px; padding:0 8px; }
.st-key-zoom_obj [data-testid="stHorizontalBlock"] { gap:34px; }
.ob-logo { margin:8px 0 0; }
.ob-hr { height:1px; background:#4a5568; margin:14px 0 22px; }
.ob-titulo { color:#fff; font-weight:700; font-size:22px; line-height:28px; margin:0 0 6px 8px; }
[class*="st-key-obj_"], [class*="st-key-obj_"] .stButton { width:100% !important; }
.stApp [class*="st-key-obj_"] .stButton button { width:100% !important; height:62px; min-height:62px; background:#dcdcdc; border:2px solid #dcdcdc;
    border-radius:8px; justify-content:flex-start; padding:0 14px; box-shadow:none;
    transition:background-color .35s ease, border-color .35s ease; }
.stApp [class*="st-key-obj_"] .stButton button:hover { border-color:#3b82f6; }
.stApp [class*="st-key-obj_"] .stButton button p { color:#111; font-size:19px; font-weight:700; line-height:1.15; text-align:left; transition:color .35s ease; }
.stApp [class*="st-key-obj_"] .stButton button::before { content:""; width:42px; height:42px; margin-right:12px; flex:none;
    background-repeat:no-repeat; background-position:center; background-size:contain; }
.stApp .st-key-btn_obj_continuar .stButton button, .stApp .st-key-btn_niv_continuar .stButton button { height:50px; min-height:50px; border-radius:10px; }
.stApp .st-key-btn_obj_continuar .stButton button p, .stApp .st-key-btn_niv_continuar .stButton button p { font-size:22px !important; }

/* colunas nunca quebram linha nas telas 4 e 5 */
.st-key-zoom_obj [data-testid="stHorizontalBlock"], .st-key-zoom_resumo [data-testid="stHorizontalBlock"] { flex-wrap:nowrap !important; }
.st-key-zoom_obj [data-testid="stColumn"], .st-key-zoom_resumo [data-testid="stColumn"] { min-width:0 !important; }
.stApp [class*="st-key-obj_"] .stButton button [data-testid="stMarkdownContainer"] { flex:1; width:auto; text-align:left; }

/* ---------- recuperar senha (2 etapas) ---------- */
.block-container .st-key-zoom_rec, .block-container .st-key-zoom_niv { zoom:__TELA_ESCALA__; width:100%; box-sizing:border-box; }
.block-container .st-key-zoom_rec { padding:0 8px; gap:0; }
.rc-logo { margin:2px 0 14px; } .rc-logo .ft-logo-p { justify-content:center; font-size:24px; }
.block-container .st-key-painel_rec { background:#131d33; border:1px solid #2a3a58; border-radius:28px; padding:16px 20px 14px; gap:10px; }
.rc-ico { display:flex; justify-content:center; margin-top:6px; } .rc-ico svg { width:38px; height:38px; }
.rc-titulo { color:#fff; font-weight:700; font-size:22px; line-height:28px; text-align:center; margin:10px 0 0; }
.rc-sub { color:#e5e7eb; font-size:14.5px; line-height:19px; text-align:center; margin:2px 0 0; }
.rc-ok { color:#22e05a; font-weight:700; font-size:16px; text-align:center; margin:4px 0 0; }
.rc-hr { height:1px; background:#4a5568; margin:14px 4px 6px; }
.rc-nota { color:#e5e7eb; font-size:14px; text-align:center; margin:2px 0 6px; }
.st-key-painel_rec [data-testid="stTextInputRootElement"] { background-color:#0a111f !important; border:1px solid #1e2a42 !important;
    border-radius:8px !important; height:41px !important; min-height:41px !important; box-shadow:none !important; }
.st-key-painel_rec div[data-baseweb="input"], .st-key-painel_rec div[data-baseweb="base-input"] { background:transparent !important; border:none !important; }
.st-key-painel_rec input { background:transparent !important; color:#fff !important; font-size:17px; font-weight:700; height:41px;
    padding-top:0; padding-bottom:0; padding-left:12px; }
.st-key-painel_rec input::placeholder { color:#f3f4f6; opacity:1; font-weight:700; }
.st-key-painel_rec [data-testid="stTextInputRootElement"] button { background:transparent !important; color:#d1d5db !important; }
.stApp .st-key-btn_rec_enviar .stButton button, .stApp .st-key-btn_rec_redef .stButton button { height:40px; min-height:40px; border-radius:14px; }
.stApp .st-key-btn_rec_enviar .stButton button p, .stApp .st-key-btn_rec_redef .stButton button p { font-size:16px !important; }
.stApp .st-key-btn_rec_voltar .stButton button p { color:#fff !important; font-weight:700 !important; font-size:16px !important; }

/* ---------- nível de experiência ---------- */
.block-container .st-key-zoom_niv { gap:16px; padding:0 8px; }
.nv-titulo { color:#fff; font-weight:700; font-size:22px; line-height:28px; margin:0 0 0 8px; }
.nv-sub { color:#e5e7eb; font-size:15px; line-height:20px; margin:0 0 0 8px; }
[class*="st-key-niv_"], [class*="st-key-niv_"] .stButton { width:100% !important; }
.stApp [class*="st-key-niv_"] .stButton button { width:100% !important; height:64px; min-height:64px; background:#18294a; border:2px solid transparent;
    border-radius:10px; justify-content:flex-start; padding:0 30px; box-shadow:none; transition:border-color .35s ease; }
.stApp [class*="st-key-niv_"] .stButton button:hover { border-color:#2d4677; }
.stApp [class*="st-key-niv_"] .stButton button [data-testid="stMarkdownContainer"] { flex:1; width:auto; text-align:left; }
.stApp [class*="st-key-niv_"] .stButton button p { color:#fff; font-size:19px; font-weight:700; line-height:1.2; text-align:left; }

/* modo desenvolvedor: botão flutuante no canto superior direito */
.st-key-dev_panel { position:fixed !important; right:8px; top:8px; z-index:9999; width:auto !important; gap:0 !important; }
.st-key-dev_panel button { background:#7c3aed !important; color:#fff !important; border:none !important; font-size:12px;
    min-height:28px; padding:2px 10px; border-radius:6px; opacity:.92; }
.st-key-dev_panel button p { color:#fff !important; font-size:12px !important; font-weight:700 !important; }
[class*="st-key-dev_ir_"] button, .st-key-dev_sair button { width:100%; justify-content:flex-start; font-size:13px; }

__FADE__
__ICONES__
</style>
"""

AZUL = "#2f8bff"


def azul(svg):
    return svg.replace("#d1d5db", AZUL)


SVG_HALTER = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 60 28' fill='#2f8bff'>"
              "<rect x='0' y='8' width='5' height='12' rx='2'/><rect x='7' y='3' width='7' height='22' rx='2.5'/>"
              "<rect x='16' y='12' width='28' height='4' rx='2'/>"
              "<rect x='46' y='3' width='7' height='22' rx='2.5'/><rect x='55' y='8' width='5' height='12' rx='2'/></svg>")
SVG_AVATAR = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100' fill='#2f8bff'>"
              "<circle cx='50' cy='27' r='24'/><path d='M8 98C8 72 26 63 50 63S92 72 92 98Z'/></svg>")

SVG_CAL_AZ, SVG_PESO_AZ, SVG_PESSOA_AZ = azul(SVG_CALENDARIO), azul(SVG_PESO), azul(SVG_PESSOA)
SVG_REGUA = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#2f8bff' stroke-width='2' "
             "stroke-linecap='round' stroke-linejoin='round'><path d='M3 17L17 3l4 4L7 21z'/>"
             "<path d='M7 13l2 2M10 10l2 2M13 7l2 2'/></svg>")
SVG_CHECK = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 40 40' fill='none' stroke='#2f8bff' stroke-width='3' "
             "stroke-linecap='round' stroke-linejoin='round'><circle cx='20' cy='20' r='17'/><path d='M12 21l6 6 11-13'/></svg>")
SVG_ALVO = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#2f8bff' stroke-width='2' "
            "stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='9'/><circle cx='12' cy='12' r='5'/>"
            "<circle cx='12' cy='12' r='1.2' fill='#2f8bff'/><path d='M12 12l8-8M17 3v4h4'/></svg>")
SVG_GRAFICO = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#2f8bff' stroke-width='2' "
               "stroke-linecap='round' stroke-linejoin='round'><path d='M3 3v18h18'/><path d='M7 15l4-4 3 3 6-7'/>"
               "<path d='M16 7h4v4'/></svg>")

# ícones dos objetivos (tela 5): aproximações simples em azul
SVG_OBJ = {
    "massa": ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'><g fill='#2f8bff'><circle cx='24' cy='9' r='5.5'/>"
              "<path d='M5 24c0-5 6-8 12-9h14c6 1 12 4 12 9v7c0 7-4 12-9 14H14c-5-2-9-7-9-14z'/></g>"
              "<path d='M24 17v13M13 27c4 3 7 3 11 0 4 3 7 3 11 0' stroke='#dcdcdc' stroke-width='2' fill='none' "
              "stroke-linecap='round'/></svg>"),
    "gordura": ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'><path d='M24 3c1 8 10 13 10 25a10 10 0 01-20 0"
                "c0-6 3-9 6-13 1 4 3 5 5 5 1-5 0-10-1-17z' fill='#2f8bff'/></svg>"),
    "peso": ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48' fill='#2f8bff'><rect x='1' y='17' width='5' height='14' rx='2'/>"
             "<rect x='7' y='11' width='7' height='26' rx='2.5'/><rect x='15' y='22' width='18' height='4' rx='2'/>"
             "<rect x='34' y='11' width='7' height='26' rx='2.5'/><rect x='42' y='17' width='5' height='14' rx='2'/></svg>"),
    "condicionamento": ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'><path d='M24 43S5 31 5 17a10 10 0 0119-4 "
                        "10 10 0 0119 4c0 14-19 26-19 26z' fill='#2f8bff'/></svg>"),
    "forca": ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'><path d='M6 38c-2-9 3-18 12-20l3-8c1.500-3.500 6-2.500 6 1l-1 7"
              "c8 0 15 5 15 15 0 4-3 7-7 7H15c-4 0-8-1-9-2z' fill='#2f8bff'/></svg>"),
    "saude": ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'><circle cx='30' cy='9' r='5' fill='#2f8bff'/>"
              "<path d='M25 18l-7 9 9 5-5 12M18 27l-9 3M27 31l9 4' stroke='#2f8bff' stroke-width='5' stroke-linecap='round' "
              "stroke-linejoin='round' fill='none'/></svg>"),
}


def css_objetivos(selecionado):
    """Ícones dos botões da tela 5 e o visual azul do botão escolhido (a troca de cor faz o fade)."""
    regras = []
    for chave, svg in SVG_OBJ.items():
        regras.append(f'.stApp .st-key-obj_{chave} .stButton button::before {{ background-image:{ref_icone(chave, svg)}; }}')
    if selecionado in SVG_OBJ:
        regras.append(f'.stApp .st-key-obj_{selecionado} .stButton button '
                      '{ background:#14284a !important; border-color:#3b82f6 !important; }')
        regras.append(f'.stApp .st-key-obj_{selecionado} .stButton button p {{ color:#fff !important; }}')
    return "\n".join(regras)



# ícones recortados das interfaces (tamanho = design x k); se o arquivo não existir, usa o desenho de reserva
IMG_AVATAR = img_icone("avatar", SVG_AVATAR, 0.87)
IMG_AVATAR_P = img_icone("avatar", SVG_AVATAR, 0.72)
IMG_HALTER = img_icone("logo_halter", SVG_HALTER, 0.8)
IMG_HALTER_P = img_icone("logo_halter", SVG_HALTER, 0.75)
AVATAR_AZUL = f'<div class="ft-avatar">{IMG_AVATAR}</div>'
LOGO = f'<div class="ft-logo">{IMG_HALTER}<span><i>Fit</i><b>Track</b></span></div>'
LOGO_P = f'<div class="ft-logo-p">{IMG_HALTER_P}<span><i>Fit</i><b>Track</b></span></div>'
ICO_HALTER_TOPO = img_icone("halter_topo", SVG_HALTER, 0.8)

ICO_CAL = img_icone("cal_azul", SVG_CAL_AZ)
ICO_PESO = img_icone("peso_azul", SVG_PESO_AZ)
ICO_PESSOA = img_icone("pessoa_azul", SVG_PESSOA_AZ)
ICO_REGUA = img_icone("regua_azul", SVG_REGUA)
ICO_CHECK = img_icone("check", SVG_CHECK)
ICO_ALVO = img_icone("alvo", SVG_ALVO)
ICO_GRAFICO = img_icone("grafico", SVG_GRAFICO)
ICO_HALTER_PQ = img_icone("halter_pq", SVG_HALTER)


COLUNAS_BOTAO = [0.3, 0.4, 0.3]  # botão azul centralizado, como no design

st.session_state.setdefault("tela", "login")
st.session_state.setdefault("msg", None)
st.session_state.setdefault("usuario", None)


def ir(tela):
    st.session_state.tela = tela
    st.session_state.msg = None
    st.session_state.fade_in = True  # a tela nova entra com fade


def aviso(texto, ok=False):
    st.session_state.msg = (texto, ok)


def mostrar_msg():
    msg = st.session_state.msg
    if msg:
        texto, ok = msg
        classe = "ft-ok" if ok else "ft-erro"
        st.markdown(f"<div class='ft-msg {classe}'>{html.escape(texto)}</div>", unsafe_allow_html=True)


def cabecalho_logo(subtitulo="Jornada Fitness"):
    """Avatar azul + logo FitTrack + subtítulo (login, recuperar senha, registrar conta)."""
    st.markdown(AVATAR_AZUL, unsafe_allow_html=True)
    st.markdown(LOGO, unsafe_allow_html=True)
    st.markdown(f"<div class='ft-sub'>{subtitulo}</div>", unsafe_allow_html=True)


def cabecalho_cadastro():
    st.markdown(f'<div class="ft-icone-halter">{ICO_HALTER_TOPO}</div>', unsafe_allow_html=True)
    st.markdown("<div class='ft-titulo'>Crie sua conta</div>", unsafe_allow_html=True)
    st.markdown("<div class='ft-sub'>Comece sua jornada com FitTrack</div>", unsafe_allow_html=True)


def transitar(tela):
    """Fade na tela toda: some suavemente e a próxima aparece com fade."""
    st.markdown("<style>.block-container { animation: ftfadeout .4s ease forwards !important; }</style>",
                unsafe_allow_html=True)
    time.sleep(0.45)
    ir(tela)
    st.session_state.fade_in = True
    st.rerun()


def destino_apos_login(email):
    if not tem_perfil(email):
        return "perfil"
    if not tem_objetivo(email):
        return "objetivos"
    if not tem_nivel(email):
        return "niveis"
    return "home"


def campo(placeholder, chave, senha=False, on_change=None):
    return st.text_input(placeholder, key=chave, placeholder=placeholder,
                         type="password" if senha else "default",
                         label_visibility="collapsed", on_change=on_change)


# ----------------------------- Telas -----------------------------
def tela_login():
    cabecalho_logo()
    with st.container(key="card_login"):
        email = campo("Email", "login_email")
        senha = campo("Senha", "login_senha", senha=True)
        _, c2, c3 = st.columns(COLUNAS_BOTAO)
        entrar = c2.button("Login", type="primary", key="btn_login")
        if c3.button("Esqueceu a senha?", type="tertiary", key="btn_esq"):
            transitar("esqueceu")  # fade: login -> recuperar senha
        if entrar:
            ok, res = login(email, senha)
            if ok:
                st.session_state.usuario = res
                ir(destino_apos_login(res))
                st.rerun()
            else:
                aviso(res)
        mostrar_msg()
        if st.button("Não tem uma conta? **Criar conta**", type="tertiary", key="btn_criar"):
            transitar("cadastro")  # fade: tela 1 -> tela 2


def tela_cadastro():
    cabecalho_cadastro()
    with st.container(key="card_cadastro"):
        email = campo("Email", "cad_email")
        senha = campo("Senha", "cad_senha", senha=True)
        conf = campo("Confirmar senha", "cad_conf", senha=True)
        _, c2, _ = st.columns(COLUNAS_BOTAO)
        continuar = c2.button("Continuar", type="primary", key="btn_continuar")
        if continuar:
            ok, res = cadastrar(email, senha, conf)
            if ok:
                st.session_state.usuario = email.strip().lower()  # já entra logado
                st.session_state.perf_gen = None
                st.session_state.objetivo = None
                transitar("perfil")  # fade: tela 2 -> tela 3
            else:
                aviso(res)
        mostrar_msg()
        st.button("Já possui uma conta? **Fazer login**", type="tertiary", key="btn_ir_login",
                  on_click=ir, args=("login",))


def enviar_codigo_por_email(email, codigo):
    resend.api_key = st.secrets["RESEND_API_KEY"]

    resend.Emails.send({
        "from": "FitTrack <onboarding@resend.dev>",
        "to": [email],
        "subject": "Código de recuperação - FitTrack",
        "html": f"""
            <h2>Recuperação de senha</h2>
            <p>Seu código é:</p>
            <h1>{codigo}</h1>
            <p>Ele expira em 15 minutos.</p>
        """
    })


SVG_CADEADO = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path d='M7 10V7a5 5 0 0110 0v3' fill='none' "
               "stroke='#2f8bff' stroke-width='2.4'/><rect x='4' y='10' width='16' height='12' rx='3' fill='#2f8bff'/>"
               "<circle cx='12' cy='15.5' r='1.7' fill='#131d33'/><rect x='11.2' y='16' width='1.6' height='3.4' rx='.8' fill='#131d33'/></svg>")
ICO_CADEADO = img_icone("lock_azul", SVG_CADEADO)


def voltar_login():
    st.session_state.codigo_enviado = False
    ir("login")


def pedir_codigo(email):
    """Etapa 1 -> gera o código e envia por email. Devolve True se pode ir para a etapa 2."""
    email = email.strip().lower()
    if not email_valido(email):
        aviso("Digite um email válido.")
        return False
    codigo = solicitar_reset(email)  # None se o email não existir (a tela não revela isso)
    st.session_state.codigo_demo = None
    if codigo:
        if MODO_DEMO:
            st.session_state.codigo_demo = codigo
        else:
            try:
                enviar_codigo_por_email(email, codigo)
            except Exception as erro:
                print(f"[FitTrack] falha ao enviar email pelo Resend: {type(erro).__name__}: {erro}", flush=True)
                aviso("Não foi possível enviar o email agora. Tente novamente em instantes.")
                return False
    st.session_state.rec_email_val = email
    st.session_state.codigo_enviado = True
    st.session_state.msg = None
    return True


def tela_esqueceu():
    enviado = st.session_state.get("codigo_enviado")
    with st.container(key="zoom_rec"):
        st.markdown(f'<div class="rc-logo">{LOGO_P}</div>', unsafe_allow_html=True)
        with st.container(key="painel_rec"):
            if enviado:
                demo = st.session_state.get("codigo_demo")
                texto = "Código enviado!" + (f" (teste: {demo})" if demo else "")
                sub_html = f'<div class="rc-ok">{html.escape(texto)}</div>'
            else:
                sub_html = '<div class="rc-sub">Não se preocupe! vamos ajudar você a recuperar o acesso à sua conta.</div>'
            st.markdown(f'<div class="rc-ico">{ICO_CADEADO}</div><div class="rc-titulo">Esqueceu sua senha?</div>'
                        f'{sub_html}<div class="rc-hr"></div>', unsafe_allow_html=True)
            if not enviado:
                email = campo("Email cadastrado", "rec_email")
                _, c2, _ = st.columns([0.285, 0.43, 0.285])
                if c2.button("Enviar código de recuperação", type="primary", key="btn_rec_enviar"):
                    if pedir_codigo(email):
                        st.rerun()
                mostrar_msg()
                st.markdown('<div class="rc-nota">Você receberá um código de 6 dígitos no seu e-mail.</div>',
                            unsafe_allow_html=True)
            else:
                cod = campo("Código de 6 dígitos", "rec_cod")
                nova = campo("Senha", "rec_nova", senha=True)
                conf = campo("Confirmar senha", "rec_conf", senha=True)
                _, c2, _ = st.columns([0.285, 0.43, 0.285])
                if c2.button("Redefinir senha", type="primary", key="btn_rec_redef"):
                    ok, res = redefinir_senha(st.session_state.get("rec_email_val") or "", cod, nova, conf)
                    if ok:
                        st.session_state.codigo_enviado = False
                        ir("login")
                        aviso(res, ok=True)
                        st.rerun()
                    else:
                        aviso(res)
                mostrar_msg()
            st.button("Voltar para login", type="tertiary", key="btn_rec_voltar", on_click=voltar_login)


DIAS_SEMANA = ["SEGUNDA-FEIRA", "TERÇA-FEIRA", "QUARTA-FEIRA", "QUINTA-FEIRA", "SEXTA-FEIRA", "SÁBADO", "DOMINGO"]
MESES = ["JANEIRO", "FEVEREIRO", "MARÇO", "ABRIL", "MAIO", "JUNHO", "JULHO", "AGOSTO", "SETEMBRO", "OUTUBRO",
         "NOVEMBRO", "DEZEMBRO"]
DIAS_CURTOS = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado", "Domingo"]
ICONE_GRUPO = {"peito": "ativ_peito", "costas": "ativ_costas", "bracos": "ativ_bracos", "ombros": "massa", "pernas": "saude"}

SVG_LAPIS = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#2f8bff' stroke-width='2' "
             "stroke-linecap='round' stroke-linejoin='round'><path d='M4 20l1-5L16 4l4 4L9 19z'/><path d='M14 6l4 4'/></svg>")
DASH_LARGURA = 714 * DASH_ESCALA

MENU_ITENS = [("inicio", "Início"), ("rotina", "Minha rotina"), ("progresso", "Progresso"), ("perfil", "Perfil")]
MENU_PNG = {"inicio": "casa", "rotina": "rotina", "progresso": "progresso", "perfil": "perfil", "sair": "sair"}
MENU_ICONES = {  # desenhos de reserva, usados só se os PNGs não estiverem na pasta assets/icones
    "inicio": "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path d='M3 11l9-8 9 8v10h-6v-6H9v6H3z' fill='#fff'/></svg>",
    "rotina": ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#fff' stroke-width='1.8' "
               "stroke-linecap='round'><rect x='3' y='5' width='18' height='16' rx='2'/><path d='M3 10h18M8 3v4M16 3v4'/></svg>"),
    "progresso": ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='#fff'><rect x='3' y='13' width='4' height='8' rx='1'/>"
                  "<rect x='10' y='9' width='4' height='12' rx='1'/><rect x='17' y='5' width='4' height='16' rx='1'/></svg>"),
    "perfil": SVG_PESSOA.replace("#d1d5db", "#fff"),
    "sair": ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#fff' stroke-width='2' "
             "stroke-linecap='round' stroke-linejoin='round'><path d='M10 4H5v16h5'/><path d='M14 8l5 4-5 4M19 12H9'/></svg>"),
}

# CSS do dashboard escrito nas medidas do design (px) e ampliado por DASH_ESCALA (sem zoom, para o menu poder ser fixo)
CSS_DASH = """
.block-container > [data-testid="stVerticalBlock"]:has(.st-key-dash_root) { justify-content:flex-start; }
.block-container .st-key-dash_root { gap:0; }
.block-container .st-key-menu_lateral { position:fixed; top:8px; bottom:8px; left:__MENU_LEFT__; width:239px; background:#15223f;
    border-radius:16px; padding:16px 12px; gap:6px; box-sizing:border-box; z-index:5; overflow:hidden; }
.block-container .st-key-conteudo_dash { margin-left:251px; max-width:446px; gap:0; }
.st-key-menu_lateral .ft-logo-p { font-size:19px; line-height:24px; gap:6px; margin-left:6px; }
.dm-hr { height:1px; background:#4a5568; margin:14px 6px 16px; }
.dm-label { color:#3b82f6; font-size:12px; font-weight:700; margin:0 8px 6px; }
[class*="st-key-mn_"], [class*="st-key-mn_"] .stButton { width:100% !important; }
.stApp [class*="st-key-mn_"] .stButton button { width:100% !important; height:46px; min-height:46px; background:transparent; border:none;
    border-radius:12px; justify-content:flex-start; padding:0 12px; box-shadow:none; }
.stApp [class*="st-key-mn_"] .stButton button [data-testid="stMarkdownContainer"] { flex:1; width:auto; text-align:left; }
.stApp [class*="st-key-mn_"] .stButton button p { color:#fff; font-size:19px; font-weight:500; text-align:left; line-height:1.1; }
.stApp [class*="st-key-mn_"] .stButton button::before { content:""; width:24px; height:24px; margin-right:14px; flex:none;
    background-repeat:no-repeat; background-position:center; background-size:contain; }
.stApp .st-key-mn_sair .stButton button p { font-size:16px; font-weight:400; }
.stApp .st-key-mn_sair .stButton button::before { width:22px; height:22px; margin-right:12px; }
.st-key-menu_sair { position:absolute !important; left:12px; right:12px; bottom:14px; gap:6px; }
.dm-hr-sair { height:1px; background:#4a5568; margin:0 6px 4px; }

.db-data { color:#fff; font-size:12px; font-weight:700; margin:8px 0 6px 12px; }
.db-ola { color:#fff; font-size:20px; font-weight:700; line-height:26px; margin:0 0 20px 12px; }
.db-ola .ic { margin-left:4px; vertical-align:-4px; }
.db-evoluir { margin:0 0 6px 12px; } .db-evoluir b { display:block; color:#fff; font-size:20px; line-height:26px; }
.db-evoluir span { display:block; color:#fff; font-size:15px; line-height:19px; }
.db-obj { background:#3b5b9a; border-radius:14px; padding:12px 14px 14px 14px; margin:8px 0 16px; }
.db-obj-l { color:#fff; font-size:11px; font-weight:700; margin-left:12px; }
.db-obj-c { display:flex; align-items:center; gap:12px; margin-top:4px; }
.db-obj-t { color:#fff; font-size:19px; font-weight:700; line-height:24px; }
.db-obj-n { color:#e5e7eb; font-size:12px; }
.db-h { color:#fff; font-size:18px; font-weight:700; line-height:24px; margin:6px 0 8px 12px; }
.db-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px; }
.db-stat { background:#18294a; border-radius:12px; padding:10px 14px 12px; }
.db-stat .ic { display:block; }
.db-stat b { display:block; color:#fff; font-size:28px; font-weight:500; line-height:32px; }
.db-stat span { display:block; color:#e5e7eb; font-size:12px; }
.block-container .st-key-db_rotina { background:#18294a; border-radius:14px; padding:14px 16px 14px; gap:10px; margin-bottom:6px; }
.db-r-t { display:flex; justify-content:space-between; align-items:center; color:#fff; font-size:17px; font-weight:700; line-height:22px; }
.db-r-s { color:#e5e7eb; font-size:13px; margin:22px 0 14px; }
.db-semana { display:flex; justify-content:space-between; padding:0 6px; }
.db-dia { display:flex; flex-direction:column; align-items:center; gap:4px; color:#fff; font-size:13px; }
.db-colchete { height:8px; border:1px solid #6b7a99; border-top:none; margin:4px 22px 6px; }
.stApp .st-key-btn_db_montar .stButton button { height:34px; min-height:34px; border-radius:6px; }
.stApp .st-key-btn_db_montar .stButton button p { font-size:14px !important; }
.db-card { background:#18294a; border-radius:14px; padding:12px 16px 12px; margin-bottom:6px; }
.db-card-topo { display:flex; justify-content:space-between; align-items:baseline; }
.db-card-topo b { color:#fff; font-size:16px; } .db-card-topo i { color:#3b82f6; font-size:9px; font-style:normal; font-weight:700; }
.db-peso { color:#fff; font-size:28px; font-weight:700; line-height:34px; margin-top:10px; }
.db-peso-s { color:#e5e7eb; font-size:10px; }
.db-grafico { display:flex; justify-content:flex-end; margin:-6px 20px 4px 0; } .db-grafico svg { width:190px; height:54px; }
.db-ativ { padding:8px 14px; }
.db-ati { display:flex; align-items:center; gap:10px; padding:5px 0; }
.db-ati > div { flex:1; } .db-ati b { display:block; color:#fff; font-size:14px; line-height:17px; } .db-ati span { display:block; color:#e5e7eb; font-size:12px; }
.db-vazio { color:#e5e7eb; font-size:13px; padding:10px 2px; }
.db-ph { background:#18294a; border-radius:14px; padding:26px 20px; color:#e5e7eb; font-size:16px; margin-top:20px; }
.db-ph b { display:block; color:#fff; font-size:20px; margin-bottom:6px; }
.db-obj-c svg, .db-stat svg, .db-r-t svg, .db-dia svg, .db-ati svg { width:20px; height:20px; }
"""


def escalar_px(css, k):
    """Multiplica todas as medidas em px do CSS por k (é assim que o dashboard cresce sem usar zoom)."""
    return re.sub(r"(?<![\w.])(-?(?:\d+\.\d+|\.\d+|\d+))px", lambda m: f"{float(m.group(1)) * k:g}px", css)


def css_dashboard(aba):
    regras = []
    for chave, svg in MENU_ICONES.items():
        regras.append(f'.stApp .st-key-mn_{chave} .stButton button::before '
                      f'{{ background-image:{ref_icone(MENU_PNG[chave], svg)}; }}')
    if aba in dict(MENU_ITENS):
        regras.append(f'.stApp .st-key-mn_{aba} .stButton button {{ background:#2e4a86 !important; }}')
        regras.append(f'.stApp .st-key-mn_{aba} .stButton button p {{ font-weight:700 !important; }}')
    return "\n".join(regras)


def css_dashboard_completo(aba):
    # o menu fica fixo na tela, alinhado à esquerda do bloco centralizado (8px compensam a barra de rolagem)
    esquerda = f"max(8px, calc(50% - {DASH_LARGURA / 2 - 8 * DASH_ESCALA + 8:g}px))"
    return escalar_px(CSS_DASH, DASH_ESCALA).replace("__MENU_LEFT__", esquerda) + "\n" + css_dashboard(aba)


def css_niveis(selecionado):
    """Descrição de cada nível dentro do botão e a borda azul do nível escolhido (a troca de cor faz o fade)."""
    regras = []
    for chave, titulo, descricao in NIVEIS:
        regras.append(f'.stApp .st-key-niv_{chave} .stButton button p::after {{ content:"{descricao}"; display:block; '
                      'font-size:15px; font-weight:400; color:#e5e7eb; line-height:1.25; }')
    if selecionado in {c for c, _, _ in NIVEIS}:
        regras.append(f'.stApp .st-key-niv_{selecionado} .stButton button {{ border-color:#3b82f6 !important; }}')
    return "\n".join(regras)


def abrir_aba(chave):
    st.session_state.aba = chave
    st.session_state.msg = None


def sair_da_conta():
    st.session_state.usuario = None
    st.session_state.objetivo = None
    st.session_state.nivel = None
    st.session_state.aba = "inicio"
    transitar("login")


def rotulo_data(d):
    dias = (date.today() - d).days
    if dias <= 0:
        return "Hoje"
    if dias == 1:
        return "Ontem"
    return DIAS_CURTOS[d.weekday()] if dias < 7 else d.strftime("%d/%m")


def grafico_peso_svg(historico):
    """Linha com os pesos registrados nos últimos 30 dias (um ponto por registro)."""
    if not historico:
        return ""
    largura, altura, margem = 180, 50, 6
    inicio = date.today() - timedelta(days=29)
    xs = [margem + max((d - inicio).days, 0) / 29 * (largura - 2 * margem) for d, _ in historico]
    kgs = [kg for _, kg in historico]
    menor, maior = min(kgs), max(kgs)
    ys = [altura / 2 if maior == menor else (altura - margem) - (kg - menor) / (maior - menor) * (altura - 2 * margem)
          for kg in kgs]
    pontos = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
    linha = f"<polyline fill='none' stroke='#2f8bff' stroke-width='1.6' points='{pontos}'/>" if len(xs) > 1 else ""
    bolas = "".join(f"<circle cx='{x:.1f}' cy='{y:.1f}' r='2.2' fill='#2f8bff'/>" for x, y in zip(xs, ys))
    return f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {largura} {altura}'>{linha}{bolas}</svg>"


def html_dashboard(p, objetivo, nivel, treinos, dias_ativos):
    k = DASH_ESCALA
    hoje = date.today()
    data = f"{DIAS_SEMANA[hoje.weekday()]}, {hoje.day} DE {MESES[hoje.month - 1]}"
    primeiro = (p["nome"].split() or ["atleta"])[0]
    chave_obj = {r: c for c, r in OBJETIVOS}.get(objetivo, "massa")
    nivel_txt = f"Nível {nivel.lower()}" if nivel else ""
    return (f'<div class="db-data">{data}</div>'
            f'<div class="db-ola">Olá {html.escape(normalizar_nome(primeiro))} {img_icone("mao", "👋", k * 0.9)}</div>'
            '<div class="db-evoluir"><b>Vamos evoluir hoje?</b><span>Sua jornada continua. Mantenha o foco!</span></div>'
            f'<div class="db-obj"><div class="db-obj-l">SEU OBJETIVO</div><div class="db-obj-c">'
            f'{img_icone(chave_obj, SVG_OBJ[chave_obj], k * 0.95)}'
            f'<div><div class="db-obj-t">{html.escape(objetivo or "Defina seu objetivo")}</div>'
            f'<div class="db-obj-n">{html.escape(nivel_txt)}</div></div></div></div>'
            '<div class="db-h">Seu resumo</div>'
            f'<div class="db-grid"><div class="db-stat">{img_icone("halter_stat", SVG_HALTER, k)}<b>{treinos}</b>'
            f'<span>Treinos realizados</span></div>'
            f'<div class="db-stat">{img_icone("chama_stat", SVG_OBJ["gordura"], k)}<b>{dias_ativos}</b>'
            f'<span>Dias ativos</span></div></div>')


def html_rotina():
    k = DASH_ESCALA
    dias = "".join(f'<div class="db-dia">{img_icone("lapis", SVG_LAPIS, k)}<span>{d}</span></div>'
                   for d in ("dom", "seg", "ter", "qua", "qui", "sex", "sab"))
    return (f'<div class="db-r-t"><span>Sua rotina</span>{img_icone("cal_rotina", SVG_CAL_AZ, k)}</div>'
            '<div class="db-r-s">Você ainda não possui uma rotina de treino</div>'
            f'<div class="db-semana">{dias}</div><div class="db-colchete"></div>')


def html_evolucao(peso_kg, historico, atividades):
    k = DASH_ESCALA
    if atividades:
        itens = "".join(
            f'<div class="db-ati">{img_icone(ICONE_GRUPO.get(a["grupo"], "massa"), SVG_OBJ["massa"], k * 0.95)}'
            f'<div><b>{html.escape(a["nome"])}</b><span>{rotulo_data(a["data"])} - {a["minutos"]} min</span></div>'
            f'{img_icone("check_ativ", SVG_CHECK, k)}</div>' for a in atividades)
    else:
        itens = '<div class="db-vazio">Nenhuma atividade registrada ainda.</div>'
    return ('<div class="db-h">Sua evolução</div><div class="db-card"><div class="db-card-topo"><b>Evolução do peso</b>'
            '<i>ÚLTIMOS 30 DIAS</i></div>'
            f'<div class="db-peso">{_fmt_num(peso_kg)} kg</div>'
            '<div class="db-peso-s">Acompanhe as mudanças ao longo do tempo.</div>'
            f'<div class="db-grafico">{grafico_peso_svg(historico)}</div></div>'
            f'<div class="db-h">Atividade recente</div><div class="db-card db-ativ">{itens}</div>')


def tela_dashboard():
    email = st.session_state.usuario or ""
    p = obter_perfil(email)
    if not p:
        ir("perfil")
        st.rerun()
        return
    aba = st.session_state.get("aba") or "inicio"
    with st.container(key="dash_root"):
        with st.container(key="menu_lateral"):  # fixo: ocupa a altura da tela e não rola
            st.markdown(f'{LOGO_P}<div class="dm-hr"></div><div class="dm-label">MENU PRINCIPAL</div>',
                        unsafe_allow_html=True)
            for chave, rotulo in MENU_ITENS:
                st.button(rotulo, key=f"mn_{chave}", on_click=abrir_aba, args=(chave,))
            with st.container(key="menu_sair"):
                st.markdown('<div class="dm-hr-sair"></div>', unsafe_allow_html=True)
                if st.button("Sair", key="mn_sair"):
                    sair_da_conta()
        with st.container(key="conteudo_dash"):
            if aba == "inicio":
                treinos, dias_ativos = resumo_treinos(email)
                st.markdown(html_dashboard(p, obter_objetivo(email), obter_nivel(email), treinos, dias_ativos),
                            unsafe_allow_html=True)
                with st.container(key="db_rotina"):
                    st.markdown(html_rotina(), unsafe_allow_html=True)
                    _, c2, _ = st.columns([0.2, 0.6, 0.2])
                    if c2.button("\\+ Montar minha rotina", type="primary", key="btn_db_montar"):
                        aviso("A montagem da rotina chega na próxima tela.")
                    mostrar_msg()
                peso = peso_atual(email) or p["peso_kg"]
                st.markdown(html_evolucao(peso, historico_peso(email), atividades_recentes(email)),
                            unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="db-ph"><b>{dict(MENU_ITENS)[aba]}</b>Esta área estará disponível em breve.</div>',
                            unsafe_allow_html=True)


MASCARA_DATA_JS = """
<script>
(function () {
  var doc = window.parent.document;
  var setter = Object.getOwnPropertyDescriptor(window.parent.HTMLInputElement.prototype, "value").set;

  function formatar(d, apagando) {
    var v = d.slice(0, 2);
    if (d.length > 2 || (d.length === 2 && !apagando)) v += "/";
    if (d.length > 2) v += d.slice(2, 4);
    if (d.length > 4 || (d.length === 4 && !apagando)) v += "/";
    if (d.length > 4) v += d.slice(4, 8);
    return v;
  }

  function ligar() {
    var el = doc.querySelector(".st-key-perf_nasc input");
    if (!el || el.dataset.mascara) return;
    el.dataset.mascara = "1";
    el.setAttribute("inputmode", "numeric");
    el.setAttribute("maxlength", "10");
    el.addEventListener("input", function (e) {
      var apagando = !!(e.inputType && e.inputType.indexOf("delete") === 0);
      var novo = formatar(el.value.replace(/\\D/g, "").slice(0, 8), apagando);
      if (novo !== el.value) {
        setter.call(el, novo);
        el.dispatchEvent(new Event("input", { bubbles: true }));
      }
    });
  }

  ligar();
  setInterval(ligar, 300);
})();
</script>
"""


FOTO_FALLBACK = """
<div class="ft-foto">
<svg width="260" height="120" viewBox="0 0 260 120" xmlns="http://www.w3.org/2000/svg">
  <rect x="20" y="40" width="22" height="40" rx="4" fill="#4b5563"/><rect x="42" y="25" width="26" height="70" rx="5" fill="#6b7280"/>
  <rect x="68" y="54" width="124" height="12" rx="6" fill="#9ca3af"/>
  <rect x="192" y="25" width="26" height="70" rx="5" fill="#6b7280"/><rect x="218" y="40" width="22" height="40" rx="4" fill="#4b5563"/>
</svg></div>
"""


def foto_halteres():
    """Mostra a foto da pasta assets, ao lado do app.py: assets/halteres.png (ou .jpg).
    Se não houver nenhuma imagem na pasta, mostra um halter desenhado no lugar."""
    pasta = Path(__file__).parent / "assets"
    candidatos = [pasta / n for n in ("halteres.png", "halteres.jpg", "halteres.jpeg")]
    if pasta.is_dir():
        candidatos += sorted(a for a in pasta.iterdir()
                             if a.suffix.lower() in (".png", ".jpg", ".jpeg", ".webp"))
    for caminho in candidatos:
        if caminho.is_file():
            tipo = {".png": "png", ".webp": "webp"}.get(caminho.suffix.lower(), "jpeg")
            dados = base64.b64encode(caminho.read_bytes()).decode()
            st.markdown(f'<img class="ft-foto-img" alt="Halteres" src="data:image/{tipo};base64,{dados}">',
                        unsafe_allow_html=True)
            return
    st.markdown(FOTO_FALLBACK, unsafe_allow_html=True)


def formatar_nome():
    """Ao sair do campo, o nome já aparece com as iniciais maiúsculas."""
    st.session_state.perf_nome = normalizar_nome(st.session_state.get("perf_nome", "") or "")


def formatar_data():
    """Ao sair do campo, 12102010 vira 12/10/2010 (reserva caso a máscara em tempo real não funcione)."""
    d = re.sub(r"\D", "", st.session_state.get("perf_nasc", "") or "")[:8]
    st.session_state.perf_nasc = (d[:2] + ("/" + d[2:4] if len(d) > 2 else "")
                                  + ("/" + d[4:] if len(d) > 4 else ""))


def escolher_genero(valor):
    st.session_state.perf_gen = valor
    st.session_state.msg = None


def tela_perfil():
    esq, dir_ = st.columns([0.56, 0.44], gap="small")
    with esq:
        with st.container(key="card_perfil"):
            st.markdown("<div class='ft-titulo-card'>Vamos conhecer você!</div>", unsafe_allow_html=True)
            nome = campo("Nome completo", "perf_nome", on_change=formatar_nome)
            nasc = campo("00/00/0000", "perf_nasc", on_change=formatar_data)
            peso = campo("Peso (kg)", "perf_peso")
            altura = campo("Altura (cm)", "perf_altura")
            st.markdown("<div class='ft-genero'>Gênero</div>", unsafe_allow_html=True)
            genero = st.session_state.get("perf_gen")
            colunas = st.columns(3)
            for col, valor, letra, rotulo in ((colunas[0], "Masculino", "m", "♂"),
                                              (colunas[1], "Feminino", "f", "♀"),
                                              (colunas[2], "Outro", "o", "Outro")):
                estado = "on" if genero == valor else "off"
                col.button(rotulo, type="tertiary", key=f"gen_{estado}_{letra}",
                           on_click=escolher_genero, args=(valor,))
            _, c2, _ = st.columns([0.17, 0.66, 0.17])
            if c2.button("Criar conta", type="primary", key="btn_criar_perfil"):
                ok, res = salvar_perfil(st.session_state.usuario, nome, nasc, peso, altura, genero)
                if ok:
                    transitar("resumo")  # fade na tela toda -> tela 4
                else:
                    aviso(res)
            mostrar_msg()
    with dir_:
        with st.container(key="painel_perfil"):
            cabecalho_logo()
            foto_halteres()
    with st.container(key="js_mask"):
        try:
            components.html(MASCARA_DATA_JS, height=0)
        except Exception:
            pass  # sem a máscara o campo continua funcionando (aceita 01011990 ou 01/01/1990)


def _fmt_num(n):
    return f"{n:.1f}".rstrip("0").rstrip(".").replace(".", ",")


RESUMO_DIREITA = (f'<div class="rs-topo">{ICO_CHECK}<span>Tudo pronto!</span></div>'
                  '<div class="rs-sub">Seu cadastro foi concluído com sucesso</div>'
                  '<div class="rs-card"><div class="rs-card-t">Agora vamos começar?</div>'
                  '<div class="rs-card-s">Queremos conhecer seus objetivos para personalizar sua experiência.</div>'
                  f'<div class="rs-li">{ICO_ALVO}<span>Descubra seu objetivo</span></div>'
                  f'<div class="rs-li">{ICO_GRAFICO}<span>Acompanhe sua evolução</span></div>'
                  f'<div class="rs-li">{ICO_HALTER_PQ}<span>Organize seus treinos</span></div></div>')


def tela_resumo():
    p = obter_perfil(st.session_state.usuario or "")
    if not p:
        ir("perfil")
        st.rerun()
        return
    nasc = date.fromisoformat(p["nascimento"])
    hoje = date.today()
    idade = hoje.year - nasc.year - ((hoje.month, hoje.day) < (nasc.month, nasc.day))
    itens = ((ICO_CAL, "Idade", f"{idade} {'Ano' if idade == 1 else 'Anos'}"),
             (ICO_PESO, "Peso", f"{_fmt_num(p['peso_kg'])} kg"),
             (ICO_PESSOA, "Gênero", p["genero"]),
             (ICO_REGUA, "Altura", f"{p['altura_cm'] / 100:.2f}".replace(".", ",") + " m"))
    lista = "".join(f'<div class="rs-item">{ico}<div><div class="rs-lbl">{rot}</div>'
                    f'<div class="rs-val">{html.escape(val)}</div></div></div>' for ico, rot, val in itens)
    esquerda = (f'{LOGO_P}<div class="rs-hr"></div><div class="rs-avatar">{IMG_AVATAR_P}</div>'
                f'<div class="rs-nome">{html.escape(normalizar_nome(p["nome"]))}</div><div class="rs-hr"></div>'
                f'<div class="rs-titulo">SEU PERFIL</div>{lista}')
    with st.container(key="zoom_resumo"):
        esq, dir_ = st.columns([0.39, 0.61], gap="small")
        with esq:
            with st.container(key="painel_resumo"):
                st.markdown(esquerda, unsafe_allow_html=True)
        with dir_:
            with st.container(key="painel_info"):
                st.markdown(RESUMO_DIREITA, unsafe_allow_html=True)
                if st.button("Vamos começar", type="primary", key="btn_comecar"):
                    transitar("objetivos")  # fade na tela toda -> tela 5


def escolher_objetivo(chave):
    st.session_state.objetivo = chave
    st.session_state.msg = None


def tela_objetivos():
    escolhido = st.session_state.get("objetivo")
    with st.container(key="zoom_obj"):
        st.markdown(f'<div class="ob-logo">{LOGO_P}</div><div class="ob-hr"></div>'
                    '<div class="ob-titulo">Vamos personalizar seus treinos!</div>', unsafe_allow_html=True)
        for i in range(0, len(OBJETIVOS), 2):
            colunas = st.columns(2, gap="small")
            for col, (chave, rotulo) in zip(colunas, OBJETIVOS[i:i + 2]):
                col.button(rotulo, key=f"obj_{chave}", on_click=escolher_objetivo, args=(chave,))
        _, c2, _ = st.columns([0.27, 0.46, 0.27])
        if c2.button("Continuar", type="primary", key="btn_obj_continuar"):
            ok, res = salvar_objetivo(st.session_state.usuario, escolhido)
            if ok:
                transitar("niveis")  # fade -> tela de nível de experiência
            else:
                aviso(res)
        mostrar_msg()


def escolher_nivel(chave):
    st.session_state.nivel = chave
    st.session_state.msg = None


def tela_niveis():
    escolhido = st.session_state.get("nivel")
    with st.container(key="zoom_niv"):
        st.markdown(f'<div class="ob-logo">{LOGO_P}</div><div class="ob-hr" style="margin-bottom:14px"></div>'
                    '<div class="nv-titulo">Qual é seu nível de experiência?</div>'
                    '<div class="nv-sub">Queremos entender sua experiência com os treinos para adaptar sua jornada.</div>',
                    unsafe_allow_html=True)
        for chave, titulo, _ in NIVEIS:
            st.button(titulo, key=f"niv_{chave}", on_click=escolher_nivel, args=(chave,))
        _, c2, _ = st.columns([0.27, 0.46, 0.27])
        if c2.button("Continuar", type="primary", key="btn_niv_continuar"):
            ok, res = salvar_nivel(st.session_state.usuario, escolhido)
            if ok:
                transitar("home")  # fade -> dashboard
            else:
                aviso(res)
        mostrar_msg()


TELAS_DEV = [("login", "1 · Login", "login"), ("cadastro", "2 · Crie sua conta", "cadastro"),
             ("perfil", "3 · Vamos conhecer você", "perfil"), ("resumo", "4 · Tudo pronto", "resumo"),
             ("objetivos", "5 · Objetivos", "objetivos"), ("niveis", "6 · Nível de experiência", "niveis"),
             ("esqueceu", "Recuperar senha · etapa 1", "esqueceu"), ("esqueceu2", "Recuperar senha · etapa 2", "esqueceu"),
             ("home", "Dashboard", "home")]


def modo_dev():
    """Liga com MODO_DEV = True (no topo do arquivo), ou FITTRACK_DEV=1 (no seu computador), ou DEV_MODE = true nos Secrets."""
    if MODO_DEV or os.environ.get("FITTRACK_DEV") == "1":
        return True
    try:
        return bool(st.secrets.get("DEV_MODE", False))
    except Exception:
        return False


def dev_ir(chave):
    """Pula direto para a tela. As telas internas usam o usuário de teste (tudo já preenchido)."""
    tela = {c: t for c, _, t in TELAS_DEV}[chave]
    if tela in ("perfil", "resumo", "objetivos", "niveis", "home"):
        st.session_state.usuario = garantir_usuario_dev()
    st.session_state.tela = tela
    st.session_state.msg = None
    st.session_state.fade_in = True  # a tela nova entra com fade
    st.session_state.aba = "inicio"
    st.session_state.codigo_enviado = chave == "esqueceu2"
    st.session_state.rec_email_val = EMAIL_DEV if chave == "esqueceu2" else None


def dev_sair():
    st.session_state.usuario = None
    st.session_state.objetivo = None
    st.session_state.nivel = None
    st.session_state.perf_gen = None
    st.session_state.codigo_enviado = False
    st.session_state.tela = "login"
    st.session_state.msg = None


def painel_dev():
    if not modo_dev():
        return
    with st.container(key="dev_panel"):
        with st.popover("🛠 DEV"):
            st.markdown(f"**tela atual:** `{st.session_state.get('tela')}`  \n"
                        f"**usuário:** `{st.session_state.get('usuario') or '-'}`")
            for chave, rotulo, _ in TELAS_DEV:
                st.button(rotulo, key=f"dev_ir_{chave}", on_click=dev_ir, args=(chave,))
            st.button("Gerar treinos e pesos de exemplo", key="dev_dados", on_click=gerar_dados_exemplo_dev)
            st.button("Zerar treinos e pesos de teste", key="dev_zerar", on_click=zerar_dados_dev)
            st.button("Sair / limpar sessão", key="dev_sair", on_click=dev_sair)


TELAS = {"login": tela_login, "cadastro": tela_cadastro, "esqueceu": tela_esqueceu,
         "perfil": tela_perfil, "resumo": tela_resumo, "objetivos": tela_objetivos, "niveis": tela_niveis,
         "home": tela_dashboard}

tela = st.session_state.tela
if tela in ("home", "perfil", "resumo", "objetivos", "niveis") and not st.session_state.usuario:  # protege a tela interna
    tela = st.session_state.tela = "login"

def css_da_tela(tela):
    """CSS dinâmico só da tela aberta: botão escolhido, ícones e o dashboard."""
    if tela == "objetivos":
        return css_objetivos(st.session_state.get("objetivo"))
    if tela == "niveis":
        return css_niveis(st.session_state.get("nivel"))
    if tela == "home":
        return css_dashboard_completo(st.session_state.get("aba") or "inicio")
    return ""


# larguras: "Registrar conta" ocupa quase toda a janela; as telas 4 e 5 seguem o tamanho do design
# "Recuperar senha" é mais comprida (vários campos): usa escalas menores para não rolar a página
HEADER_USADO, CARD_USADO = HEADER_ESCALA, CARD_ESCALA

if tela == "perfil":
    LARGURA_CSS = "min(1280px, 96vw)"
elif tela == "resumo":
    LARGURA_CSS = f"{round(711 * TELA_ESCALA)}px"
elif tela == "objetivos":
    LARGURA_CSS = f"{round(709 * TELA_ESCALA)}px"
elif tela == "esqueceu":
    LARGURA_CSS = f"{round(713 * TELA_ESCALA)}px"
elif tela == "niveis":
    LARGURA_CSS = f"{round(716 * TELA_ESCALA)}px"
elif tela == "home":
    LARGURA_CSS = f"{round(DASH_LARGURA)}px"
else:
    LARGURA_CSS = f"{round(LARGURAS[tela] * CARD_USADO)}px"

# fade-in só quando a tela acabou de ser trocada por transitar()
# o atraso de .3s mantém a tela invisível até o conteúdo novo estar pronto (evita ver a tela anterior esticada)
FADE_CSS = ".block-container { animation: ftfadein .6s ease .3s both; }" if st.session_state.pop("fade_in", False) else ""

css_extra = css_icones(tela) + "\n" + css_da_tela(tela)  # antes do replace: registra as variáveis dos ícones

st.markdown(CSS.replace("__LARGURA__", LARGURA_CSS)
            .replace("__PERFIL_ESCALA__", str(PERFIL_ESCALA))
            .replace("__CARD_ESCALA__", str(CARD_USADO))
            .replace("__HEADER_ESCALA__", str(HEADER_USADO))
            .replace("__TELA_ESCALA__", str(TELA_ESCALA))
            .replace("__ESCALA__", str(ESCALA))
            .replace("__ICONES__", css_vars_icones() + "\n" + css_extra)
            .replace("__FADE__", FADE_CSS),
            unsafe_allow_html=True)
painel_dev()  # só aparece no modo desenvolvedor
with st.empty().container():
    TELAS[tela]()
