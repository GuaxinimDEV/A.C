"""
Tranca o site com senha antes de publicar.

Uso:
    pip install cryptography
    python trancar.py                      -> usa estudio-linha.html e gera index.html
    python trancar.py meu-arquivo.html     -> gera index.html a partir de outro arquivo

O conteúdo do site é criptografado (AES-256). Sem a senha, quem abrir o
index.html ou olhar o código só vê a tela de senha e um bloco embaralhado.
Guarde a senha: ela não fica salva em lugar nenhum.
"""
import base64, getpass, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 300_000
entrada = sys.argv[1] if len(sys.argv) > 1 else "estudio-linha.html"
saida = sys.argv[2] if len(sys.argv) > 2 else "index.html"

if not os.path.exists(entrada):
    sys.exit(f"Não achei o arquivo {entrada}. Coloque este script na mesma pasta do site.")

senha = getpass.getpass("Escolha a senha do site: ")
if len(senha) < 6:
    sys.exit("Use uma senha com pelo menos 6 caracteres.")
if getpass.getpass("Repita a senha: ") != senha:
    sys.exit("As senhas não são iguais. Rode de novo.")

html = open(entrada, encoding="utf-8").read().encode("utf-8")
salt, iv = os.urandom(16), os.urandom(12)
chave = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(senha.encode("utf-8"))
dados = AESGCM(chave).encrypt(iv, html, None)
b64 = lambda b: base64.b64encode(b).decode()

pagina = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Estúdio Linha · Acesso restrito</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>📓</text></svg>">
<style>
:root{--bg:#D9DEE3;--panel:#fff;--ink:#1C2230;--muted:#5E6673;--line:#D8DCE0;--cobalt:#2F4BD8;--danger:#B3261E}
@media (prefers-color-scheme:dark){:root{--bg:#23272E;--panel:#1B1F26;--ink:#EEF0F3;--muted:#A3AAB5;--line:#353B45;--cobalt:#7F93FF;--danger:#FF8A80}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,"Segoe UI",sans-serif;padding:20px}
form{width:min(380px,100%);background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:28px}
.brand{font-weight:800;font-size:24px;letter-spacing:-.02em;margin:0 0 4px}
.brand span{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--cobalt);margin-left:4px}
p{margin:0 0 20px;color:var(--muted);font-size:15px;line-height:1.5}
label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}
input[type=password]{width:100%;font:inherit;font-size:16px;padding:12px;border:1px solid var(--line);border-radius:10px;background:var(--panel);color:var(--ink)}
input:focus-visible,button:focus-visible{outline:2px solid var(--cobalt);outline-offset:2px}
.check{display:flex;gap:8px;align-items:center;margin:14px 0 18px;font-size:14px;color:var(--ink)}
button{width:100%;font:inherit;font-weight:600;padding:13px;border:0;border-radius:999px;background:var(--cobalt);color:#fff;cursor:pointer}
button[disabled]{opacity:.6;cursor:wait}
.err{color:var(--danger);font-size:14px;min-height:1.4em;margin-top:10px}
</style>
</head>
<body>
<form id="f" autocomplete="off">
  <div class="brand">Estúdio Linha<span></span></div>
  <p>Site em construção. Digite a senha que você recebeu para ver a versão de testes.</p>
  <label for="pw">Senha</label>
  <input type="password" id="pw" required autofocus>
  <label class="check"><input type="checkbox" id="rem"> Lembrar neste aparelho</label>
  <button id="go">Entrar</button>
  <div class="err" id="err" role="alert"></div>
</form>
<script>
const SALT="__SALT__",IV="__IV__",ITER=__ITER__,DATA="__DATA__",KEY="estudio-linha-senha";
const b=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function abrir(pw){
  const km=await crypto.subtle.importKey("raw",new TextEncoder().encode(pw),"PBKDF2",false,["deriveKey"]);
  const k=await crypto.subtle.deriveKey({name:"PBKDF2",salt:b(SALT),iterations:ITER,hash:"SHA-256"},km,{name:"AES-GCM",length:256},false,["decrypt"]);
  const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:b(IV)},k,b(DATA));
  const html=new TextDecoder().decode(pt);
  document.open();document.write(html);document.close();
}
const guarda={get(){try{return localStorage.getItem(KEY)||sessionStorage.getItem(KEY);}catch(e){return null;}},
  set(v,lembrar){try{(lembrar?localStorage:sessionStorage).setItem(KEY,v);}catch(e){}},
  limpa(){try{localStorage.removeItem(KEY);sessionStorage.removeItem(KEY);}catch(e){}}};
const salva=guarda.get();
if(salva)abrir(salva).catch(()=>guarda.limpa());
document.getElementById("pw").addEventListener("input",()=>document.getElementById("err").textContent="");
document.getElementById("f").addEventListener("submit",async e=>{
  e.preventDefault();
  const pw=document.getElementById("pw").value,btn=document.getElementById("go"),err=document.getElementById("err");
  if(!pw){err.textContent="Digite a senha.";return;}
  btn.disabled=true;btn.textContent="Abrindo…";
  const lembrar=document.getElementById("rem").checked;
  try{guarda.set(pw,lembrar);await abrir(pw);}
  catch(x){guarda.limpa();err.textContent="Senha incorreta. Confira e tente de novo.";btn.disabled=false;btn.textContent="Entrar";document.getElementById("pw").select();}
});
</script>
</body>
</html>"""
pagina = (pagina.replace("__SALT__", b64(salt)).replace("__IV__", b64(iv))
          .replace("__ITER__", str(ITER)).replace("__DATA__", b64(dados)))
open(saida, "w", encoding="utf-8").write(pagina)
print(f"Pronto! {saida} criado ({len(pagina)//1024} KB). Publique este arquivo no lugar do original.")
