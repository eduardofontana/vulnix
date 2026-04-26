# VULNIX - Scanner de Vulnerabilidades Web

```
 /$$    /$$ /$$   /$$ /$$       /$$   /$$ /$$$$$$ /$$   /$$
| $$   | $$| $$  | $$| $$      | $$$ | $$|_  $$_/| $$  / $$
| $$   | $$| $$  | $$| $$      | $$$$| $$  | $$  |  $$/ $$/
|  $$ / $$/| $$  | $$| $$      | $$ $$ $$  | $$   \  $$$$/
 \  $$ $$/ | $$  | $$| $$      | $$  $$$$  | $$    >$$  $$
  \  $$$/  | $$  | $$| $$      | $$\  $$$  | $$   /$$/\  $$
   \  $/   |  $$$$$$/| $$$$$$$$| $$ \  $$ /$$$$$$| $$  \ $$
    \_/     \______/ |________/|__/  \__/|______/|__/  |__/ v1.3.0
```

<p align="center">
  <img src="https://img.shields.io/badge/Versao-1.3.0-blue" alt="Versão">
  <img src="https://img.shields.io/badge/Python-3.11+-green" alt="Python">
  <img src="https://img.shields.io/badge/Licenca-MIT-red" alt="Licença">
</p>

## Visão Geral

**VULNIX** é um scanner de vulnerabilidades web para testes de segurança autorizados, com foco em reconhecimento para bug bounty, detecção de CMS e análise de riscos de aplicação.

> Aviso legal: use somente em alvos com autorização explícita. Uso não autorizado é ilegal.

## Funcionalidades

### Varredura de Vulnerabilidades
- Detecção de SQL Injection
- Detecção de XSS (Refletido, Armazenado e DOM)
- Análise de Security Headers
- Descoberta de diretórios
- Verificações de CSRF / IDOR / Auth
- HTTP Desync (Request Smuggling)
- Cloud Metadata SSRF
- Detecção de WAF + testes de bypass
- Testes de segurança para WebSocket
- Inteligência de CVE (NVD + KEV + EPSS)

### Vulnerabilidades Avançadas (v1.3.0)
- SSTI (Server-Side Template Injection)
- LFI/RFI (Local/Remote File Inclusion)
- Race Condition
- XXE (XML External Entity)
- Vulnerabilidades baseadas em DOM

### Reconhecimento (v1.3.0)
- DNS Lookup (A, AAAA, MX, NS, TXT, CNAME, SOA)
- Port Scanner com detecção de serviço (100+ portas)
- Análise de certificado SSL/TLS
- Analisador de robots.txt e sitemap.xml
- Extração de links (internos, externos e endpoints de API)
- Scanner de segurança para GraphQL
- Detecção de limitação de taxa (rate limiting)
- Detecção de takeover de subdomínio (18+ serviços)
- Análise de Wayback Machine
- WHOIS lookup
- Extração de segredos em JavaScript (AWS, Google, Stripe, JWT etc.)
- Descoberta de parâmetros ocultos
- Fuzzing de conteúdo

### Detecção de CMS (v1.3.0)
- WordPress + plugins potencialmente vulneráveis
- Joomla + componentes
- Drupal
- Magento
- Shopify
- Wix
- Squarespace
- Ghost
- PrestaShop
- Bitrix
- SharePoint

### Relatórios
- Formatos: JSON / HTML / Text / SARIF
- Seção consolidada de Recon
- Insights por módulo (evidência + remediação)

### Operação Avançada
- Modo `--safe` (reduz pressão de requests e desativa checks mais agressivos)
- Modo `--aggressive` (aumenta pressão e ativa checks ativos)
- Retomada com `--resume` + checkpoints em `--checkpoint-dir`
- Exportação adicional em JSONL (`--jsonl-output`)
- Diff com baseline (`--baseline` + `--diff-output`)
- Envio opcional para SIEM (`--siem splunk|elk`)

## Instalação

Pré-requisitos:
- Python 3.11+
- pip

Instale as dependências:

```bash
pip install -r requirements.txt
```

## Uso

Ajuda:

```bash
python run.py --help
```

Exemplo básico:

```bash
python run.py https://example.com
```

### Perfis de Scan

```bash
# rápido
python run.py https://example.com --mode quick

# padrão
python run.py https://example.com --mode standard

# profundo
python run.py https://example.com --mode deep -v -o reports/deep_scan
```

### Recon Completo

```bash
python run.py https://example.com --recon-all
```

### Ferramentas Individuais

```bash
# CMS Detection
python run.py https://example.com --cms

# CVE Intelligence
python run.py https://example.com --cve-intel

# DNS + Portas + SSL
python run.py https://example.com --dns --port-scan --ssl

# GraphQL
python run.py https://example.com --graphql

# Subdomain Takeover
python run.py example.com --takeover

# JS Secrets
python run.py https://example.com --js-secrets

# Fuzzing de diretórios
python run.py https://example.com --fuzz
```

### Vulnerabilidades Avançadas

```bash
python run.py https://example.com --ssti --lfi --race --xxe --dom
```

### Scan Completo

```bash
python run.py https://example.com \
  --recon-all \
  --cms \
  --cve-intel \
  --ssti --lfi --race --xxe --dom \
  --format both \
  -o reports/full_scan \
  -v
```

### Atualizar Cache de CVE

```bash
python run.py --update-cve-cache
```

## Principais Argumentos

| Argumento | Descrição |
|---|---|
| `--mode` | Perfil de scan (`quick`, `standard`, `deep`) |
| `--safe` | Modo seguro (menos agressivo) |
| `--aggressive` | Modo agressivo (mais ativo) |
| `-t, --timeout` | Timeout de request em segundos |
| `-d, --depth` | Profundidade máxima de crawl |
| `-u, --urls` | Máximo de URLs para crawl |
| `--no-sqli` | Desativa SQLi |
| `--no-xss` | Desativa XSS |
| `--no-headers` | Desativa análise de headers |
| `--dirscan` | Ativa descoberta de diretórios |
| `--recon` | Ativa recon para bug bounty |
| `--recon-all` | Executa todas as ferramentas de recon |
| `--dns` | Ativa DNS lookup |
| `--port-scan` | Ativa varredura de portas |
| `--ssl` | Ativa análise SSL/TLS |
| `--graphql` | Ativa scanner GraphQL |
| `--rate-limit` | Ativa detecção de rate limiting |
| `--cms` | Ativa detecção de CMS |
| `--ssti` | Testa SSTI |
| `--lfi` | Testa LFI |
| `--race` | Testa race condition |
| `--xxe` | Testa XXE |
| `--dom` | Testa vulnerabilidades DOM |
| `-f, --format` | Formato de saída |
| `-o, --output` | Prefixo do arquivo de saída |
| `--resume` | Arquivo de estado para retomar scan |
| `--checkpoint-dir` | Pasta para checkpoints |
| `--jsonl-output` | Salva findings em JSONL |
| `--baseline` | JSON base para diff |
| `--diff-output` | Salva diff em JSON |
| `--siem` | Envia eventos para `splunk` ou `elk` |
| `-v, --verbose` | Modo verboso |

## Estrutura do Projeto

```text
vulnix/
├── cli/
│   ├── main.py
│   └── commands.py
├── config/
│   └── settings.py
├── core/
│   ├── scanner.py
│   ├── crawler.py
│   ├── fuzzing.py
│   ├── request_engine.py
│   └── ...
├── modules/
│   ├── sqli.py
│   ├── xss.py
│   ├── headers.py
│   ├── recon.py
│   ├── ssl.py
│   ├── graphql.py
│   ├── cms_detect.py
│   ├── advanced_vulns.py
│   ├── recon_more.py
│   └── recon_advanced.py
├── tests/
├── requirements.txt
├── run.py
└── README.md
```

## Testes

```bash
python -m pytest tests -q
```

## Uso Ético

1. Use apenas em alvos autorizados.
2. Não realize exploração destrutiva.
3. Respeite limites de taxa de requisição.
4. Documente escopo e execução.

## Licença

MIT.
