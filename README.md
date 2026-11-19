# Sistema de Votação Eletrônica Seguro

Repositório desenvolvido para a disciplina de **Criptografia**.
Implementação de um sistema de votação eletrônica seguro ponta a ponta com ElGamal Exponencial (cifragem aditivamente homomórfica), chave pública conjunta ($N \ge 3$ autoridades), Quadro Público (*Bulletin Board*) encadeado por SHA-256 e assinaturas digitais RSA.

---

## Estrutura do Projeto

```text
sistema-votacao-criptografia/
├── docs/
│   ├── especificacao_projeto.md        # Especificação completa, regras e critérios de avaliação
│   ├── plano_geral.tex                 # Documento LaTeX com o plano geral e arquitetura
│   ├── orientacoes_para_relatorio.md   # Divisão de tarefas do relatório para os 5 integrantes
│   ├── relatorio_temporario.md         # Estrutura do relatório técnico em Markdown
│   └── guias/                          # Guias didáticos das fases
│       ├── guia_primeira_fase.md       # Fase 1: Primitivas criptográficas
│       ├── guia_segunda_fase.md        # Fase 2: Setup da Eleição
│       ├── guia_terceira_fase.md       # Fase 3: Votação e Quadro Público
│       └── guia_quarta_fase.md         # Fase 4: Apuração e Decifração Distribuída
├── src/
│   ├── __init__.py                     # Pacote Python
│   ├── cripto_base.py                  # Fase 1: Primitivas ElGamal, RSA, SHA-256 e Grupo RFC 3526
│   ├── setup_eleicao.py                # Fase 2: Autoridades eleitorais, chave conjunta h e eleitores
│   ├── votacao.py                      # Fase 3: Quadro público append-only, cédulas, recibos e validações
│   └── apuracao.py                     # Fase 4: Apuração homomórfica e decifração distribuída
├── .gitignore
├── README.md
└── requirements.txt              # Dependências do projeto
```

---

## Como Configurar e Executar

### 1. Criar e ativar o ambiente virtual

```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Instalar as dependências

```bash
pip install -r requirements.txt
```

### 3. Execução das Fases

* **Testar Primitivas Criptográficas (Fase 1):**
  ```bash
  python3 src/cripto_base.py
  ```

* **Testar Setup da Eleição e Chave Conjunta (Fase 2):**
  ```bash
  python3 src/setup_eleicao.py
  ```

* **Testar Fluxo de Votação e Ataques Bloqueados (Fase 3):**
  ```bash
  python3 src/votacao.py
  ```

* **Testar Apuração Homomórfica e Falha de Autoridade (Fase 4):**
  ```bash
  python3 src/apuracao.py
  ```

---