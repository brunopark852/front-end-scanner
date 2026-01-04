# 🛡️ DOM-XRAY (Front-End Scanner)

Ferramenta de auditoria de segurança focada em **Client-Side**. Projetada para analisar aplicações modernas (SPA) em busca de segredos vazados e configurações inseguras.

## 🚀 Funcionalidades

* **Header Analysis:** Verifica proteções contra XSS, Clickjacking e MIME Sniffing.
* **JS Hunter:** Baixa e analisa arquivos JavaScript (.js) externos em busca de chaves de API (AWS, Google, Stripe).
* **Inline Audit:** Vasculha scripts embutidos no HTML.
* **Deep Regex:** Utiliza padrões avançados para detectar +10 tipos de credenciais vazadas.

## 📦 Instalação

git clone https://github.com/brunopark852/front-end-scanner.git
cd front-end-scanner
pip install requests


## 💀 Uso

python3 dom-xray.py https://alvo.com


---
**Autor:** Bruno Rodrigo
