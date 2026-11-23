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
TELA_ESCALA = 1.3  # tamanho das telas "Tudo pronto" e "Vamos personalizar seus treinos" (1 = design)
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


def salvar_perfil(email, nome, nascimento, peso, altura, genero):
    """Tela 'Registrar conta' -> botão Criar conta."""
    nome = " ".join((nome or "").split())
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
        return True, "Perfil criado com sucesso!"
    finally:
        con.close()


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


# =========================== INTERFACE (Streamlit) ===========================
st.set_page_config(page_title="FitTrack", page_icon="💪", layout="centered")
criar_tabelas()

LARGURAS = {"login": 620, "esqueceu": 620, "home": 620, "cadastro": 580, "perfil": 620}

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


def css_icones():
    """Ícones de email e cadeado dentro dos campos (como no design)."""
    grupos = ((SVG_EMAIL, ["login_email", "cad_email", "rec_email"]),
              (SVG_LOCK, ["login_senha", "cad_senha", "cad_conf", "rec_nova", "rec_conf"]),
              (SVG_PESSOA, ["perf_nome"]), (SVG_CALENDARIO, ["perf_nasc"]),
              (SVG_PESO, ["perf_peso"]), (SVG_ALTURA, ["perf_altura"]))
    regras = []
    for svg, chaves in grupos:
        url = 'url("data:image/svg+xml,' + quote(svg) + '")'
        for k in chaves:
            regras.append(f'.st-key-{k} [data-testid="stTextInputRootElement"] {{ background-image:{url} !important; '
                          f'background-repeat:no-repeat; background-position:10px center; background-size:22px 22px; }}')
            regras.append(f'.st-key-{k} input {{ padding-left:44px !important; }}')
    # botões de gênero: ♂ azul, ♀ rosa, pessoa cinza, cada um com o círculo ao lado
    url_pessoa = 'url("data:image/svg+xml,' + quote(SVG_PESSOA) + '")'
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
        regras.append(f'{topo}o .stButton button[kind="tertiary"] p {{ font-size:0 !important; display:flex; '
                      'flex-direction:column; align-items:center; gap:3px; }')
        regras.append(f'{topo}o .stButton button[kind="tertiary"] p::after {{ content:"Outro"; font-size:11px; '
                      'font-weight:400; color:#e5e7eb; line-height:1; }')
        regras.append(f'{topo}o .stButton button[kind="tertiary"] p::before {{ content:""; display:inline-block; '
                      f'width:34px; height:34px; background:{url_pessoa} center/contain no-repeat; }}')
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
.block-container { max-width:__LARGURA__; padding:8px 0; zoom:__ESCALA__; min-height:100vh; box-sizing:border-box;
                   display:flex; flex-direction:column; justify-content:center; }
.block-container [data-testid="stVerticalBlock"] { gap:0; }
.block-container [data-testid="stHorizontalBlock"] { gap:8px; }

/* textos */
.ft-avatar { display:flex; justify-content:center; height:76px; margin-bottom:14px; zoom:__HEADER_ESCALA__; }
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
.stApp .st-key-btn_obj_continuar .stButton button { height:50px; min-height:50px; border-radius:10px; }
.stApp .st-key-btn_obj_continuar .stButton button p { font-size:22px !important; }

/* colunas nunca quebram linha nas telas 4 e 5 */
.st-key-zoom_obj [data-testid="stHorizontalBlock"], .st-key-zoom_resumo [data-testid="stHorizontalBlock"] { flex-wrap:nowrap !important; }
.st-key-zoom_obj [data-testid="stColumn"], .st-key-zoom_resumo [data-testid="stColumn"] { min-width:0 !important; }
.stApp [class*="st-key-obj_"] .stButton button [data-testid="stMarkdownContainer"] { flex:1; width:auto; text-align:left; }

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
AVATAR_AZUL = f'<div class="ft-avatar">{SVG_AVATAR}</div>'
LOGO = f'<div class="ft-logo">{SVG_HALTER}<span><i>Fit</i><b>Track</b></span></div>'
LOGO_P = f'<div class="ft-logo-p">{SVG_HALTER}<span><i>Fit</i><b>Track</b></span></div>'

ICO_CAL, ICO_PESO, ICO_PESSOA = azul(SVG_CALENDARIO), azul(SVG_PESO), azul(SVG_PESSOA)
ICO_REGUA = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#2f8bff' stroke-width='2' "
             "stroke-linecap='round' stroke-linejoin='round'><path d='M3 17L17 3l4 4L7 21z'/>"
             "<path d='M7 13l2 2M10 10l2 2M13 7l2 2'/></svg>")
ICO_CHECK = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 40 40' fill='none' stroke='#2f8bff' stroke-width='3' "
             "stroke-linecap='round' stroke-linejoin='round'><circle cx='20' cy='20' r='17'/><path d='M12 21l6 6 11-13'/></svg>")
ICO_ALVO = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#2f8bff' stroke-width='2' "
            "stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='9'/><circle cx='12' cy='12' r='5'/>"
            "<circle cx='12' cy='12' r='1.2' fill='#2f8bff'/><path d='M12 12l8-8M17 3v4h4'/></svg>")
ICO_GRAFICO = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='#2f8bff' stroke-width='2' "
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
        url = 'url("data:image/svg+xml,' + quote(svg) + '")'
        regras.append(f'.stApp .st-key-obj_{chave} .stButton button::before {{ background-image:{url}; }}')
    if selecionado in SVG_OBJ:
        regras.append(f'.stApp .st-key-obj_{selecionado} .stButton button '
                      '{ background:#14284a !important; border-color:#3b82f6 !important; }')
        regras.append(f'.stApp .st-key-obj_{selecionado} .stButton button p {{ color:#fff !important; }}')
    return "\n".join(regras)


COLUNAS_BOTAO = [0.3, 0.4, 0.3]  # botão azul centralizado, como no design

st.session_state.setdefault("tela", "login")
st.session_state.setdefault("msg", None)
st.session_state.setdefault("usuario", None)


def ir(tela):
    st.session_state.tela = tela
    st.session_state.msg = None


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
    st.markdown(f'<div class="ft-icone-halter">{SVG_HALTER}</div>', unsafe_allow_html=True)
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
        c3.button("Esqueceu a senha?", type="tertiary", key="btn_esq",
                  on_click=ir, args=("esqueceu",))
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


def tela_esqueceu():
    cabecalho_logo("Recuperar senha")
    with st.container(key="card_esqueceu"):
        email = campo("Email", "rec_email")
        _, c2, _ = st.columns(COLUNAS_BOTAO)
        if c2.button("Enviar código", type="primary", key="btn_enviar"):
            codigo = solicitar_reset(email)
            st.session_state.codigo_enviado = True
            if codigo:
                if MODO_DEMO:
                    aviso(f"[SIMULAÇÃO DE EMAIL] Seu código: {codigo}", ok=True)
                else:
                    try:
                        enviar_codigo_por_email(email.strip().lower(), codigo)
                        aviso("Se o email estiver cadastrado, um código foi enviado.", ok=True)
                    except Exception as erro:
                        print(f"[FitTrack] falha ao enviar email pelo Resend: {type(erro).__name__}: {erro}", flush=True)
                        aviso("Não foi possível enviar o email agora. Tente novamente em instantes.")
            else:
                aviso("Se o email estiver cadastrado, um código foi enviado.", ok=True)
        mostrar_msg()

        if st.session_state.get("codigo_enviado"):
            cod = campo("Código de 6 dígitos", "rec_cod")
            nova = campo("Nova senha", "rec_nova", senha=True)
            conf = campo("Confirmar nova senha", "rec_conf", senha=True)
            _, c2, _ = st.columns(COLUNAS_BOTAO)
            if c2.button("Redefinir senha", type="primary", key="btn_redef"):
                ok, res = redefinir_senha(email, cod, nova, conf)
                if ok:
                    st.session_state.codigo_enviado = False
                    ir("login")
                    aviso(res, ok=True)
                    st.rerun()
                else:
                    aviso(res)
                    st.rerun()
        st.button("Voltar ao login", type="tertiary", key="btn_voltar",
                  on_click=ir, args=("login",))


def tela_home():
    cabecalho_logo()
    with st.container(key="card_home"):
        nome = obter_nome(st.session_state.usuario or "")
        quem = html.escape(nome or st.session_state.usuario or "")
        objetivo = obter_objetivo(st.session_state.usuario or "")
        extra = f"<br>Objetivo: {html.escape(objetivo)}" if objetivo else ""
        st.markdown(f"<div class='ft-bemvindo'>Bem-vindo(a) ao FitTrack!<br>{quem}{extra}</div>",
                    unsafe_allow_html=True)
        _, c2, _ = st.columns(COLUNAS_BOTAO)
        if c2.button("Sair", type="primary", key="btn_sair"):
            st.session_state.usuario = None
            ir("login")
            st.rerun()


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
            nome = campo("Nome completo", "perf_nome")
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
                  f'<div class="rs-li">{SVG_HALTER}<span>Organize seus treinos</span></div></div>')


def tela_resumo():
    p = obter_perfil(st.session_state.usuario or "")
    if not p:
        ir("perfil")
        st.rerun()
    nasc = date.fromisoformat(p["nascimento"])
    hoje = date.today()
    idade = hoje.year - nasc.year - ((hoje.month, hoje.day) < (nasc.month, nasc.day))
    itens = ((ICO_CAL, "Idade", f"{idade} {'Ano' if idade == 1 else 'Anos'}"),
             (ICO_PESO, "Peso", f"{_fmt_num(p['peso_kg'])} kg"),
             (ICO_PESSOA, "Gênero", p["genero"]),
             (ICO_REGUA, "Altura", f"{p['altura_cm'] / 100:.2f}".replace(".", ",") + " m"))
    lista = "".join(f'<div class="rs-item">{ico}<div><div class="rs-lbl">{rot}</div>'
                    f'<div class="rs-val">{html.escape(val)}</div></div></div>' for ico, rot, val in itens)
    esquerda = (f'{LOGO_P}<div class="rs-hr"></div><div class="rs-avatar">{SVG_AVATAR}</div>'
                f'<div class="rs-nome">{html.escape(p["nome"])}</div><div class="rs-hr"></div>'
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
                ir("home")
                st.rerun()
            else:
                aviso(res)
        mostrar_msg()


TELAS = {"login": tela_login, "cadastro": tela_cadastro, "esqueceu": tela_esqueceu,
         "perfil": tela_perfil, "resumo": tela_resumo, "objetivos": tela_objetivos, "home": tela_home}

tela = st.session_state.tela
if tela in ("home", "perfil", "resumo", "objetivos") and not st.session_state.usuario:  # protege a tela interna
    tela = st.session_state.tela = "login"

# larguras: "Registrar conta" ocupa quase toda a janela; as telas 4 e 5 seguem o tamanho do design
# "Recuperar senha" é mais comprida (vários campos): usa escalas menores para não rolar a página
HEADER_USADO, CARD_USADO = (1.0, 1.1) if tela == "esqueceu" else (HEADER_ESCALA, CARD_ESCALA)

if tela == "perfil":
    LARGURA_CSS = "min(1280px, 96vw)"
elif tela == "resumo":
    LARGURA_CSS = f"{round(711 * TELA_ESCALA)}px"
elif tela == "objetivos":
    LARGURA_CSS = f"{round(709 * TELA_ESCALA)}px"
else:
    LARGURA_CSS = f"{round(LARGURAS[tela] * CARD_USADO)}px"

# fade-in só quando a tela acabou de ser trocada por transitar()
FADE_CSS = ".block-container { animation: ftfadein .6s ease both; }" if st.session_state.pop("fade_in", False) else ""

st.markdown(CSS.replace("__LARGURA__", LARGURA_CSS)
            .replace("__PERFIL_ESCALA__", str(PERFIL_ESCALA))
            .replace("__CARD_ESCALA__", str(CARD_USADO))
            .replace("__HEADER_ESCALA__", str(HEADER_USADO))
            .replace("__TELA_ESCALA__", str(TELA_ESCALA))
            .replace("__ESCALA__", str(ESCALA))
            .replace("__ICONES__", css_icones() + "\n" + css_objetivos(st.session_state.get("objetivo")))
            .replace("__FADE__", FADE_CSS),
            unsafe_allow_html=True)
with st.empty().container():
    TELAS[tela]()
