# VULNIX - Scanner de Vulnerabilidade Web

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.11+-green" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-red" alt="License">
</p>

---

## 🔰 Introdução

**VULNIX** é um scanner de vulnerabilidade web de nível profissional, inspirado em ferramentas como OWASP ZAP e Burp Suite. Desenvolvido para testes de segurança educativos e autorizados em aplicações web.

> ⚠️ **AVISO IMPORTANTE**: Esta ferramenta destina-se exclusivamente para testes de segurança em aplicações web que você tem permissão legal para testar. O uso não autorizado é ilegal e punishable por lei.

---

## 🎯 Características

### Módulos Principais

- **🕷️ Crawler (Motor de Descoberta)**
  - Descoberta automática de endpoints
  - Extração de formulários e parâmetros
  - Controle de profundidade
  - Evita duplicatas e loops infinitos

- **🌐 Request Engine**
  - Requisições HTTP assíncronas (httpx)
  - Retry automático
  - User-Agent rotation
  - Suporte a cookies e sessões

- **💉 Módulos de Detecção**
  - **SQL Injection**: Detecção básica de injeção SQL
  - **XSS (Reflected)**: Detecção de Cross-Site Scripting
  - **Security Headers**: Análise de headers de segurança
  - **Directory Discovery**: Descoberta de diretórios (opcional)

- **📊 Sistema de Relatórios**
  - JSON report
  - HTML report (estilo hacker)
  - Relatório em texto

---

## 🛠️ Instalação

### Pré-requisitos

- Python 3.11+
- pip (gerenciador de pacotes)

### Instalação das Dependências

```bash
pip install -r requirements.txt
```

---

## 🚀 Uso

### Verificar Argumentos

```bash
python run.py --help
```

### Exemplo Básico

```bash
python run.py https://example.com
```

### Com Opções

```bash
# Escaneamento rápido
python run.py http://localhost:8080 -d 2

# Com relatórios
python run.py https://example.com -o scan_report

# Sem SQL injection
python run.py target.local --no-sqli

# Apenas JSON
python run.py https://test.app --format json

# Verboso
python run.py https://example.com -v
```

### Opções Disponíveis

| Argumento | Descrição | Padrão |
|-----------|-----------|--------|
| `-t, --timeout` | Timeout da requisição (segundos) | 30 |
| `-d, --depth` | Profundidade máxima do crawler | 3 |
| `-u, --urls` | Máximo de URLs para crawlar | 100 |
| `--no-sqli` | Desabilitar scanning SQLi | False |
| `--no-xss` | Desabilitar scanning XSS | False |
| `--no-headers` | Desabilitar análise de headers | False |
| `--dirscan` | Habilitar descoberta de diretórios | False |
| `-o, --output` | Prefixo do arquivo de saída | None |
| `-f, --format` | Formato do relatório (json, html, text, both) | both |
| `-v, --verbose` | Saída detalhada | False |

---

## 📁 Estrutura do Projeto

```
vulnix/
├── core/
│   ├── crawler.py        # Motor de descoberta
│   ├── scanner.py        # Motor principal de scanning
│   ├── request_engine.py #Requisições HTTP
│   ├── fuzzing.py       # Motor de fuzzing
│   └── analyzer.py     # Sistema de relatórios
├── modules/
│   ├── sqli.py         # Detector SQLi
│   ├── xss.py          # Detector XSS
│   └── headers.py      # Analisador de headers
├── cli/
│   ├── main.py         # Entry point
│   └── commands.py     # Comandos CLI
├── config/
│   └── settings.py     # Configurações
├── wordlists/
│   └── common_paths.txt # Wordlist padrão
├── reports/            # Relatórios gerados
├── tests/              # Testes
├── requirements.txt
├── run.py
└── README.md
```

---

## 📋 Exemplo de Saída

### Banner

```
   _    ____   ____ ___ ___   __        _______   _   _    _    ____  __  __
  | |  / ___| / ___|_ _|_ _|   \      | ____| | | | |  / \  |  \/  |
  | |  \___ \| |    | | | |     \____ |  _|   | |_| | / _ \ | |\/| |
  |_|  |____/ \___| |___|___|     |___||_|___| |___| /___/ |_| _|_
                                                         v1.0.0
 [green]Scan. Detect. Exploit (Ethically).[/green]
```

### Resumo do Scan

```
┌─────────────────────────────────────────┐
│ Scan Summary                           │
├─────────────────────────────────────────┤
│ CRITICAL    │ 0                        │
│ HIGH        │ 2                        │
│ MEDIUM      │ 5                        │
│ LOW         │ 3                        │
│ INFO        │ 8                        │
└─────────────────────────────────────────┘
```

### Tabela de Vulnerabilidades

```
┌──────────┬──────────────────┬──────────────────────┬─────────────┐
│ Severity │ Type             │ URL                 │ Parameter   │
├──────────┼──────────────────┼──────────────────────┼─────────────┤
│ HIGH     │ sql_injection    │ http://example.com   │ id          │
│ MEDIUM   │ xss              │ http://example.com   │ name        │
└──────────┴──────────────────┴──────────────────────┴─────────────┘
```

---

## 🐛 Testes

### Executar Testes

```bash
python -m pytest tests/
```

### Executar com Coverage

```bash
python -m pytest --cov=vulnix tests/
```

---

## ⚙️ Configurações

As configurações podem ser ajustadas em `config/settings.py`:

```python
MAX_DEPTH = 3
MAX_URLS = 100
TIMEOUT = 30
MAX_RETRIES = 3
DELAY = 0.5
ENABLE_SQLI = True
ENABLE_XSS = True
ENABLE_HEADERS = True
ENABLE_DIRSCAN = False
```

---

## 🛡️ Requisitos Éticos

1. **Utilize apenas em alvos autorizados** - Tenha permissão por escrito do proprietário
2. **Não explore beyond detection** - Apenas detecte, não explore
3. **Respeite rate limits** - Não sobrecarregue o alvo
4. **Documente suas ações** - Mantenha logs de todos os testes

---

## 📄 Licença

Este projeto é distribuído sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

---

## 🤝 Contribuição

Contribuições são bem-vindas! Sinta-se livre para:

1. Fork o projeto
2. Criar uma branch (`git checkout -b feature/nova-feature`)
3. Commit suas mudanças (`git commit -m 'Add nova feature'`)
4. Push para a branch (`git push origin feature/nova-feature`)
5. Abrir um Pull Request

---

## 📞 Suporte

- 📧 Email: suporte@vulnix.com
- 📌 Issues: https://github.com/anomalyco/vulnix/issues

---

## 🙏 Agradecimentos

- [OWASP](https://owasp.org/) - Padrões de segurança
- [httpx](https://www.python-httpx.org/) - Cliente HTTP assíncrono
- [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/) - Parsing HTML
- [Rich](https://rich.readthedocs.io/) - Interface CLI bonita

---

**Desenvolvido com ⚔️ por especialistas em segurança cibernética**

```
" scan. Detect. Exploit (Ethically)."
```