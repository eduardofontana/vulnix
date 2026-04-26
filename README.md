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
- DNS Lookup (A, AAAA, MX, NS, TXT, CNAME)
- Port Scanner com detecção de serviço (até 100 portas via `--top-ports`)
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
- Formatos: JSON / HTML / Text
- Seção consolidada de Recon
- Insights por módulo (evidência + remediação)

### Operação Avançada
- Modo `--safe` (reduz pressão de requests e desativa checks mais agressivos)
- Modo `--aggressive` (aumenta pressão e ativa checks ativos)
- Filtro de confiança alta (`--high-confidence-only`) para reduzir ruído em terminal e relatórios
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

Dependências opcionais (recursos específicos):

```bash
# necessário para --whois
pip install python-whois

# necessário para executar os testes
pip install pytest
```

## Variáveis de Ambiente

| Variável | Uso |
|---|---|
| `NVD_API_KEY` | Chave opcional para melhorar limite/rate da API NVD no módulo de CVE Intel |
| `JIRA_URL` | URL base do Jira para integração em `integrations/jira.py` |
| `JIRA_PROJECT_KEY` | Chave do projeto Jira |
| `JIRA_USERNAME` | Usuário do Jira |
| `JIRA_API_TOKEN` | Token de API do Jira |

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

## Saídas e Artefatos

- Sem `-o/--output`, o scan mostra resultados no terminal e não grava os relatórios principais em arquivo.
- Com `-o reports/meu_scan`, o CLI grava:
`reports/meu_scan.json`, `reports/meu_scan.html`, `reports/meu_scan.txt` (conforme `--format`).
- `--jsonl-output findings.jsonl` grava findings em JSONL.
- `--resume vulnix_state.json` usa/atualiza arquivo de estado para retomada.
- `--checkpoint-dir checkpoints` grava checkpoints periódicos durante o scan.
- `--baseline baseline.json --diff-output diff.json` compara findings atuais com baseline e salva o diff.
- `--siem splunk|elk` envia até 200 findings para endpoints locais padrão:
`http://localhost:8088/services/collector/event` (Splunk) e
`http://localhost:9200/vulnix-findings/_doc` (ELK).

## Modos de Scan

- `quick`: foco em checks essenciais, menor cobertura.
- `standard`: comportamento padrão (equilíbrio entre cobertura e custo).
- `deep`: habilita checks mais agressivos/avançados (ex.: CSRF, IDOR, Auth, HTTP Desync, Cloud Metadata, WAF, WebSocket, CVE Intel).
- `--safe`: reduz concorrência/pressão e desativa alguns checks ativos.
- `--aggressive`: aumenta concorrência/pressão e força checks ativos.

## Principais Argumentos

| Argumento | Descrição |
|---|---|
| `-t, --timeout` | Timeout de request em segundos |
| `-d, --depth` | Profundidade máxima de crawl |
| `-u, --urls` | Máximo de URLs para crawl |
| `--mode` | Perfil de scan (`quick`, `standard`, `deep`) |
| `-q, --quick` | Scan rápido (top 10 testes) |
| `--no-sqli` | Desativa SQLi |
| `--no-xss` | Desativa XSS |
| `--no-headers` | Desativa análise de headers |
| `--dirscan` | Ativa descoberta de diretórios |
| `--http-desync` | Ativa checks de HTTP desync/request smuggling |
| `--cloud-metadata` | Ativa checks de SSRF em metadata de cloud |
| `--waf` | Ativa detecção de WAF |
| `--waf-bypass` | Ativa testes de bypass de WAF |
| `--websocket` | Ativa testes de segurança para WebSocket |
| `--cve-intel` | Ativa correlação de CVE (NVD + KEV + EPSS) |
| `--cve-intel-offline` | Usa apenas cache local para CVE intel |
| `--update-cve-cache` | Atualiza cache local de CVE antes do scan |
| `--subs` | Enumera subdomínios |
| `--subs-brute` | Enumera subdomínios com brute force |
| `--param-fuzz` | Faz fuzzing de parâmetros |
| `--cors` | Verifica configuração CORS |
| `--ssrf` | Verifica SSRF |
| `--redirect` | Verifica open redirect |
| `--tech` | Faz fingerprint de tecnologias |
| `--recon` | Ativa recon de bug bounty |
| `--recon-all` | Executa todas as ferramentas de recon e checks avançados |
| `--dns` | Ativa DNS lookup |
| `--dns-records` | Tipos DNS em CSV (ex.: `A,MX,NS,TXT,CNAME`) |
| `--port-scan` | Ativa varredura de portas |
| `--port-range` | Faixa de portas (ex.: `1-1000`) |
| `--top-ports` | Quantidade de portas mais comuns (padrão: `20`) |
| `--ssl` | Ativa análise SSL/TLS |
| `--tls-check` | Verifica vulnerabilidades TLS conhecidas |
| `--robots` | Analisa `robots.txt` |
| `--sitemap` | Analisa `sitemap.xml` |
| `--links` | Extrai links de páginas |
| `--graphql` | Ativa scanner GraphQL |
| `--rate-limit` | Ativa detecção de rate limiting |
| `--proxy` | Usa proxy HTTP (ex.: `http://host:port`) |
| `--cms` | Ativa detecção de CMS |
| `--takeover` | Verifica subdomain takeover |
| `--wayback` | Analisa snapshots do Wayback Machine |
| `--whois` | Faz lookup WHOIS |
| `--js-secrets` | Extrai segredos em JavaScript |
| `--params` | Descobre parâmetros ocultos |
| `--fuzz` | Fuzzing de diretórios e arquivos |
| `--pattern` | Busca padrões sensíveis |
| `--ssti` | Testa SSTI |
| `--lfi` | Testa LFI |
| `--race` | Testa race condition |
| `--xxe` | Testa XXE |
| `--dom` | Testa vulnerabilidades DOM |
| `--extract-links` | Alias para extração de links (`--links`) |
| `--safe` | Modo seguro (menos agressivo) |
| `--aggressive` | Modo agressivo (mais ativo) |
| `-f, --format` | Formato de saída (`json`, `html`, `text`, `both`) |
| `-o, --output` | Prefixo do arquivo de saída |
| `--resume` | Arquivo de estado para retomar scan |
| `--checkpoint-dir` | Pasta para checkpoints |
| `--high-confidence-only` | Exibe e salva apenas findings com alta confiança |
| `--jsonl-output` | Salva findings em JSONL |
| `--baseline` | JSON base para diff |
| `--diff-output` | Salva diff em JSON |
| `--siem` | Envia eventos para `splunk` ou `elk` |
| `-v, --verbose` | Modo verboso |

## Estrutura do Projeto

```text
vulnix/
├── checkpoints/
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
├── data/
│   └── cve_intel_cache.json
├── integrations/
│   └── jira.py
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
│   ├── recon_advanced.py
│   └── pdf_report.py
├── reports/
├── tests/
├── wordlists/
├── requirements.txt
├── run.py
├── vulnix_state.json
└── README.md
```

## Integrações e Recursos Extras (Código)

- SARIF: disponível via `ReportGenerator.generate_sarif_report(...)` em `core/analyzer.py` (não exposto no `--format` do CLI atual).
- PDF: gerador em `modules/pdf_report.py` (`PDFReportGenerator`).
- Jira: exportador em `integrations/jira.py` (`JiraExporter` e utilitários CSV).

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
