import hashlib
import html
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta

import streamlit as st

# ----------------------------- Configurações -----------------------------
DB_NAME = os.environ.get("FITTRACK_DB", "fittrack.db")
MIN_SENHA = 8
ITERACOES = 200_000
ESCALA = 2        # aumenta tudo (quadros, textos, ícones) em proporção; tente 1.5, 2 ou 2.2
MODO_DEMO = True  # True: mostra o código de recuperação na tela. Em produção, use False e envie por email.


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
        return True, "Conta criada com sucesso! Faça login."
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


# =========================== INTERFACE (Streamlit) ===========================
st.set_page_config(page_title="Fit Track", page_icon="💪", layout="centered")
criar_tabelas()

LARGURAS = {"login": 620, "esqueceu": 620, "home": 620, "cadastro": 580}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&display=swap');
html, body, [class*="st-"], .stApp { font-family:'Space Grotesk',sans-serif; }
.stApp { background:#0b1220; }
header[data-testid="stHeader"], #MainMenu, footer { display:none; }
.block-container { max-width:__LARGURA__px; padding-top:1.5rem; padding-bottom:1rem; zoom:__ESCALA__; }

/* textos */
.ft-avatar { display:flex; justify-content:center; }
.ft-titulo { color:#fff; font-weight:700; font-size:28px; text-align:center; margin:6px 0 0 0; }
.ft-sub { color:#e5e7eb; font-size:19px; text-align:center; margin:2px 0 14px 0; }
.ft-msg { text-align:center; font-size:14px; min-height:18px; }
.ft-erro { color:#fca5a5; } .ft-ok { color:#86efac; }
.ft-bemvindo { color:#fff; text-align:center; font-size:18px; padding:10px; }

/* cartão escuro */
.st-key-card { background:#2b3340; border-radius:14px; padding:12px 6px; }
.st-key-card [data-testid="stVerticalBlock"] { gap:0.4rem; }

/* campos de texto e senha */
.st-key-card div[data-baseweb="input"] { background:#5b616c; border-radius:8px; border:none; height:34px; }
.st-key-card div[data-baseweb="base-input"] { background:transparent; }
.st-key-card input { color:#fff; font-size:18px; height:34px; padding-top:0; padding-bottom:0; }
.st-key-card input::placeholder { color:#f3f4f6; opacity:1; }
.st-key-card div[data-baseweb="input"] button { background:transparent; color:#d1d5db; }
.st-key-card [data-testid="stTextInput"] { margin-bottom:0; }

/* botões */
.stButton, .stButton button { width:100%; }
.stButton button[kind="primary"], .stButton button[data-testid="stBaseButton-primary"] {
    background:#2563eb; color:#fff; font-weight:700; font-size:16px; border:none;
    border-radius:6px; min-height:34px; height:34px; padding:0; }
.stButton button[kind="primary"]:hover { background:#1d4ed8; color:#fff; }
.stButton button[kind="tertiary"], .stButton button[data-testid="stBaseButton-tertiary"] {
    background:transparent; color:#e5e7eb; border:none; box-shadow:none; font-size:16px;
    min-height:34px; justify-content:center; padding:0; }
.stButton button[kind="tertiary"]:hover { color:#fff; background:transparent; }
.st-key-btn_esq button { justify-content:flex-end !important; }
</style>
"""

AVATAR = """
<div class="ft-avatar">
<svg width="112" height="112" viewBox="0 0 112 112" xmlns="http://www.w3.org/2000/svg">
  <circle cx="56" cy="56" r="52" fill="#d9d9d9" stroke="#000" stroke-width="6"/>
  <circle cx="56" cy="44" r="16" fill="#d9d9d9" stroke="#000" stroke-width="6"/>
  <path d="M26 92 C28 68 84 68 86 92" fill="#d9d9d9" stroke="#000" stroke-width="6"/>
</svg></div>
"""

COLUNAS_BOTAO = [0.31, 0.38, 0.31]  # botão azul centralizado, como no design

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


def cabecalho(titulo, subtitulo=None):
    st.markdown(AVATAR, unsafe_allow_html=True)
    st.markdown(f"<div class='ft-titulo'>{titulo}</div>", unsafe_allow_html=True)
    if subtitulo:
        st.markdown(f"<div class='ft-sub'>{subtitulo}</div>", unsafe_allow_html=True)


def campo(placeholder, chave, senha=False):
    return st.text_input(placeholder, key=chave, placeholder=placeholder,
                         type="password" if senha else "default",
                         label_visibility="collapsed")


# ----------------------------- Telas -----------------------------
def tela_login():
    cabecalho("Fit Track", "Jornada Fitness")
    with st.container(key="card"):
        email = campo("✉️  Email", "login_email")
        senha = campo("🔒  Senha", "login_senha", senha=True)
        _, c2, c3 = st.columns(COLUNAS_BOTAO)
        entrar = c2.button("Login", type="primary", key="btn_login")
        c3.button("Esqueceu a senha?", type="tertiary", key="btn_esq",
                  on_click=ir, args=("esqueceu",))
        if entrar:
            ok, res = login(email, senha)
            if ok:
                st.session_state.usuario = res
                ir("home")
                st.rerun()
            else:
                aviso(res)
        mostrar_msg()
        st.button("Criar conta", type="tertiary", key="btn_criar", on_click=ir, args=("cadastro",))


def tela_cadastro():
    cabecalho("Criar conta")
    with st.container(key="card"):
        email = campo("✉️  Email", "cad_email")
        senha = campo("🔒  Senha", "cad_senha", senha=True)
        conf = campo("🔒  Confirmar senha", "cad_conf", senha=True)
        _, c2, _ = st.columns(COLUNAS_BOTAO)
        continuar = c2.button("Continuar", type="primary", key="btn_continuar")
        if continuar:
            ok, res = cadastrar(email, senha, conf)
            if ok:
                ir("login")
                aviso(res, ok=True)
                st.rerun()
            else:
                aviso(res)
        mostrar_msg()
        st.button("Já possui uma conta? Fazer login", type="tertiary", key="btn_ir_login",
                  on_click=ir, args=("login",))


def enviar_codigo_por_email(email, codigo):
    """Em produção, envie o código por email aqui (SMTP, SendGrid, Resend...)."""
    pass


def tela_esqueceu():
    cabecalho("Recuperar senha")
    with st.container(key="card"):
        email = campo("✉️  Email", "rec_email")
        _, c2, _ = st.columns(COLUNAS_BOTAO)
        if c2.button("Enviar código", type="primary", key="btn_enviar"):
            codigo = solicitar_reset(email)
            st.session_state.codigo_enviado = True
            if codigo:
                if MODO_DEMO:
                    aviso(f"[SIMULAÇÃO DE EMAIL] Seu código: {codigo}", ok=True)
                else:
                    enviar_codigo_por_email(email, codigo)
                    aviso("Se o email estiver cadastrado, um código foi enviado.", ok=True)
            else:
                aviso("Se o email estiver cadastrado, um código foi enviado.", ok=True)
        mostrar_msg()

        if st.session_state.get("codigo_enviado"):
            cod = campo("#  Código de 6 dígitos", "rec_cod")
            nova = campo("🔒  Nova senha", "rec_nova", senha=True)
            conf = campo("🔒  Confirmar nova senha", "rec_conf", senha=True)
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
    cabecalho("Fit Track", "Jornada Fitness")
    with st.container(key="card"):
        email = html.escape(st.session_state.usuario or "")
        st.markdown(f"<div class='ft-bemvindo'>Bem-vindo(a) ao Fit Track!<br>{email}</div>",
                    unsafe_allow_html=True)
        _, c2, _ = st.columns(COLUNAS_BOTAO)
        if c2.button("Sair", type="primary", key="btn_sair"):
            st.session_state.usuario = None
            ir("login")
            st.rerun()


TELAS = {"login": tela_login, "cadastro": tela_cadastro,
         "esqueceu": tela_esqueceu, "home": tela_home}

tela = st.session_state.tela
if tela == "home" and not st.session_state.usuario:  # protege a tela interna
    tela = st.session_state.tela = "login"

st.markdown(CSS.replace("__LARGURA__", str(LARGURAS[tela])).replace("__ESCALA__", str(ESCALA)),
            unsafe_allow_html=True)
TELAS[tela]()
