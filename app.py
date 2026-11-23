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
from datetime import date, datetime, timedelta
from pathlib import Path

from urllib.parse import quote

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
        con.execute("""CREATE TABLE IF NOT EXISTS perfis (
            usuario_id INTEGER PRIMARY KEY,
            nome TEXT NOT NULL,
            nascimento TEXT NOT NULL,
            peso_kg REAL NOT NULL,
            altura_cm REAL NOT NULL,
            genero TEXT NOT NULL,
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


GENEROS = ["Masculino", "Feminino", "Prefiro não dizer"]


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
        regras.append(f'{topo}o .stButton button[kind="tertiary"] p {{ font-size:0 !important; }}')
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
.ft-avatar { display:flex; justify-content:center; height:112px; zoom:__HEADER_ESCALA__; }
.ft-avatar svg { display:block; }
.ft-titulo { color:#fff; font-weight:700; font-size:27px; text-align:center; margin:0; line-height:34px; zoom:__HEADER_ESCALA__; }
.ft-sub { color:#e5e7eb; font-size:19px; text-align:center; margin:0 0 36px 0; line-height:26px; zoom:__HEADER_ESCALA__; }
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
.ft-titulo-card { color:#fff; font-weight:700; font-size:26px; text-align:center; line-height:34px; margin:0; }
.ft-genero { color:#e5e7eb; font-size:17px; text-align:center; line-height:22px; margin-top:4px; }
.st-key-painel_perfil .ft-sub { margin-bottom:10px; }
.st-key-painel_perfil .ft-titulo, .st-key-painel_perfil .ft-sub, .st-key-painel_perfil .ft-avatar { position:relative; z-index:2; }
.st-key-painel_perfil [data-testid="stImage"] { width:100% !important; }
.st-key-painel_perfil img { width:calc(100% + (100vw - min(1280px, 96vw)) / 2) !important; max-width:none !important;
    height:370px; margin-top:-30px; position:relative; z-index:0; object-fit:cover; display:block;
    /* degradê: a foto some suavemente no fundo escuro, em cima e embaixo */
    -webkit-mask-image:linear-gradient(to bottom, transparent 0%, #000 28%, #000 72%, transparent 100%);
            mask-image:linear-gradient(to bottom, transparent 0%, #000 28%, #000 72%, transparent 100%); }
.ft-foto { height:370px; margin-top:-30px; display:flex; align-items:center; justify-content:center;
           background:linear-gradient(160deg,#1b2433 0%,#0b1220 100%); }

__ICONES__
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


def cabecalho(titulo, subtitulo=None):
    st.markdown(AVATAR, unsafe_allow_html=True)
    st.markdown(f"<div class='ft-titulo'>{titulo}</div>", unsafe_allow_html=True)
    if subtitulo:
        st.markdown(f"<div class='ft-sub'>{subtitulo}</div>", unsafe_allow_html=True)


def campo(placeholder, chave, senha=False, on_change=None):
    return st.text_input(placeholder, key=chave, placeholder=placeholder,
                         type="password" if senha else "default",
                         label_visibility="collapsed", on_change=on_change)


# ----------------------------- Telas -----------------------------
def tela_login():
    cabecalho("FitTrack", "Jornada Fitness")
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
                ir("home" if tem_perfil(res) else "perfil")
                st.rerun()
            else:
                aviso(res)
        mostrar_msg()
        st.button("Criar conta", type="tertiary", key="btn_criar", on_click=ir, args=("cadastro",))


def tela_cadastro():
    cabecalho("Criar conta")
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
                ir("perfil")  # vai direto para a tela "Registrar conta"
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
                    enviar_codigo_por_email(email, codigo)
                    aviso("Se o email estiver cadastrado, um código foi enviado.", ok=True)
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
    cabecalho("FitTrack", "Jornada Fitness")
    with st.container(key="card_home"):
        nome = obter_nome(st.session_state.usuario or "")
        quem = html.escape(nome or st.session_state.usuario or "")
        st.markdown(f"<div class='ft-bemvindo'>Bem-vindo(a) ao FitTrack!<br>{quem}</div>",
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
            st.markdown("<div class='ft-titulo-card'>Registrar conta</div>", unsafe_allow_html=True)
            nome = campo("Nome completo", "perf_nome")
            nasc = campo("00/00/0000", "perf_nasc", on_change=formatar_data)
            peso = campo("Peso (kg)", "perf_peso")
            altura = campo("Altura (cm)", "perf_altura")
            st.markdown("<div class='ft-genero'>Gênero</div>", unsafe_allow_html=True)
            genero = st.session_state.get("perf_gen")
            colunas = st.columns(3)
            for col, valor, letra, rotulo in ((colunas[0], "Masculino", "m", "♂"),
                                              (colunas[1], "Feminino", "f", "♀"),
                                              (colunas[2], "Prefiro não dizer", "o", "Prefiro não dizer")):
                estado = "on" if genero == valor else "off"
                col.button(rotulo, type="tertiary", key=f"gen_{estado}_{letra}",
                           on_click=escolher_genero, args=(valor,))
            _, c2, _ = st.columns([0.17, 0.66, 0.17])
            if c2.button("Criar conta", type="primary", key="btn_criar_perfil"):
                ok, res = salvar_perfil(st.session_state.usuario, nome, nasc, peso, altura, genero)
                if ok:
                    ir("home")
                    aviso(res, ok=True)
                    st.rerun()
                else:
                    aviso(res)
            mostrar_msg()
    with dir_:
        with st.container(key="painel_perfil"):
            cabecalho("FitTrack", "Jornada Fitness")
            foto_halteres()
    with st.container(key="js_mask"):
        try:
            components.html(MASCARA_DATA_JS, height=0)
        except Exception:
            pass  # sem a máscara o campo continua funcionando (aceita 01011990 ou 01/01/1990)


TELAS = {"login": tela_login, "cadastro": tela_cadastro, "esqueceu": tela_esqueceu,
         "perfil": tela_perfil, "home": tela_home}

tela = st.session_state.tela
if tela in ("home", "perfil") and not st.session_state.usuario:  # protege a tela interna
    tela = st.session_state.tela = "login"

# "Registrar conta" ocupa quase toda a largura da janela; as demais telas ficam centralizadas
LARGURA_CSS = ("min(1280px, 96vw)" if tela == "perfil"
               else f"{round(LARGURAS[tela] * CARD_ESCALA)}px")

st.markdown(CSS.replace("__LARGURA__", LARGURA_CSS)
            .replace("__PERFIL_ESCALA__", str(PERFIL_ESCALA))
            .replace("__CARD_ESCALA__", str(CARD_ESCALA))
            .replace("__HEADER_ESCALA__", str(HEADER_ESCALA)).replace("__ESCALA__", str(ESCALA)).replace("__ICONES__", css_icones()),
            unsafe_allow_html=True)
with st.empty().container():
    TELAS[tela]()
