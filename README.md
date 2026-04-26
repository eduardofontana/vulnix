# VULNIX - Scanner de Vulnerabilidade Web

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.11+-green" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-red" alt="License">
</p>

---

## Introdução

**VULNIX** é um scanner de vulnerabilidade web para testes de segurança autorizados, com foco em automação prática de recon e detecção.

> Aviso: use somente em alvos com autorização explícita. Uso não autorizado é ilegal.

---

## Principais recursos

- Crawler de endpoints e formulários
- Engine HTTP assíncrona com retry/cookies/rate-limit
- Detectores:
  - SQL Injection
  - XSS
  - Security Headers
  - Directory Discovery
  - CSRF / IDOR / Auth checks
  - HTTP Desync (Request Smuggling)
  - Cloud Metadata SSRF
  - WAF detection + bypass checks
  - WebSocket security testing
- Recon:
  - Subdomain enumeration
  - Technology fingerprint
  - Hidden parameter fuzzing
- Relatórios:
  - JSON / HTML / Texto / SARIF
  - Seção Recon consolidada
  - Module Insights (evidence + remediation)

---

## Instalação

Pré-requisitos:

- Python 3.11+
- pip

Instalação:

```bash
pip install -r requirements.txt
```

---

## Uso

Ajuda:

```bash
python run.py --help
```

Exemplo básico:

```bash
python run.py https://example.com
```

### Presets de scan

```bash
# rápido
python run.py https://example.com --mode quick

# padrão
python run.py https://example.com --mode standard

# profundo
python run.py https://example.com --mode deep -v -o reports/deep_scan
```

### Exemplo completo com módulos avançados

```bash
python run.py https://example.com \
  --http-desync \
  --cloud-metadata \
  --waf \
  --waf-bypass \
  --websocket \
  --subs \
  --param-fuzz \
  --tech \
  --format both \
  -o reports/scan_full \
  -v
```

---

## Opções principais

| Argumento | Descrição | Padrão |
|---|---|---|
| `--mode` | Perfil de scan (`quick`, `standard`, `deep`) | `standard` |
| `-t, --timeout` | Timeout por requisição (segundos) | `30` |
| `-d, --depth` | Profundidade máxima do crawler | `3` |
| `-u, --urls` | Máximo de URLs a crawlar | `100` |
| `--no-sqli` | Desabilita SQLi | `false` |
| `--no-xss` | Desabilita XSS | `false` |
| `--no-headers` | Desabilita headers | `false` |
| `--dirscan` | Habilita directory discovery | `false` |
| `--http-desync` | Habilita HTTP desync/smuggling | `false` |
| `--cloud-metadata` | Habilita cloud metadata SSRF | `false` |
| `--waf` | Habilita detecção de WAF | `false` |
| `--waf-bypass` | Habilita testes de bypass de WAF | `false` |
| `--websocket` | Habilita testes de segurança WebSocket | `false` |
| `--subs` | Habilita enumeração de subdomínios | `false` |
| `--subs-brute` | Habilita brute-force de subdomínios | `false` |
| `--param-fuzz` | Habilita fuzz de parâmetros | `false` |
| `--cors` | Habilita checagem de CORS | `false` |
| `--ssrf` | Habilita checagem de SSRF | `false` |
| `--redirect` | Habilita checagem de open redirect | `false` |
| `--tech` | Habilita fingerprint de tecnologia | `false` |
| `--recon` | Ativa recon completo | `false` |
| `-f, --format` | Formato de relatório (`json`, `html`, `text`, `both`) | `both` |
| `-o, --output` | Prefixo de arquivo de saída | `None` |
| `-v, --verbose` | Verbose | `false` |

---

## Estrutura do projeto

```text
vulnix/
├── cli/
├── config/
├── core/
├── integrations/
├── modules/
├── tests/
├── wordlists/
├── requirements.txt
├── run.py
└── README.md
```

---

## Testes

```bash
python -m pytest tests -q
```

---

## Ética e uso responsável

1. Use apenas em alvos autorizados.
2. Não faça exploração destrutiva.
3. Respeite limites de requisição.
4. Documente escopo e execução.

---

## Licença

MIT.
