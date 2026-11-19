# Orientações para Escrita do Relatório Técnico

Este documento define a divisão de trabalho e as diretrizes para a elaboração do **Relatório Técnico (máximo de 10 páginas)** do Sistema de Votação Eletrônica Seguro, considerando uma equipe de **5 integrantes**, onde cada um liderou o desenvolvimento de uma fase do projeto.

O relatório final será redigido a partir do arquivo [docs/relatorio_temporario.md](file:///home/alan/sistema-votacao-criptografia/docs/relatorio_temporario.md) e posteriormente convertido para LaTeX (`.tex`).

---

## Divisão Individual por Integrante (Baseada nas Fases)

---

### Integrante 1 (Responsável pela Fase 1: Primitivas Matemáticas e Criptográficas)

#### Seções a preencher no relatório:
* **Seção 8: Parâmetros e Algoritmos Criptográficos**
  * `8.1` Grupo Cíclico e Parâmetros (RFC 3526 MODP - 2048 bits) e Justificativa.
  * `8.2` Assinaturas RSA (2048 bits com padding PSS e SHA-256) e Justificativa.
  * `8.3` Função Hash (SHA-256) e Justificativa.
  * `8.4` Gerador de Números Aleatórios Criptograficamente Seguro (`secrets` do Python).
* **Subseção 4.1: Cifragem ElGamal Exponencial Vetorial** (Parte matemática das primitivas).
* **Subseção 5.3 (Trecho Matemático):** A lógica de busca exaustiva do logaritmo discreto ($g^M \bmod p$).

#### O que explicar em cada seção (Diretrizes técnicas):
* **Sobre o Grupo RFC 3526:** Explicar por que usar o Grupo 14 MODP (primo seguro $p$ onde $q = (p-1)/2$ também é primo, evitando ataques de Pohlig-Hellman). Citar que 2048 bits oferecem segurança equivalente a 112 bits simétricos (padrão NIST aceito até 2030+). Explicar por que o gerador $g = 2$ é eficiente.
* **Sobre Aritmética Modular:** Justificar o uso de `pow(base, exp, mod)` nativo do Python (algoritmo *Square-and-Multiply*) em vez de `(base ** exp) % mod`, demonstrando que evita estouro de memória RAM.
* **Sobre o Inverso Modular:** Explicar como a divisão é feita em $\mathbb{Z}_p^*$ através do Pequeno Teorema de Fermat ($a^{-1} \equiv a^{p-2} \pmod p$) ou do Algoritmo Euclidiano Estendido.
* **Sobre RSA e Padding PSS:** Explicar por que o padding PSS (*Probabilistic Signature Scheme*) foi escolhido no lugar do PKCS#1 v1.5 (PSS possui prova formal de segurança no modelo de oráculo aleatório).
* **Sobre Entropia:** Explicar a diferença crítica entre o módulo `random` (Mersenne Twister, previsível) e `secrets` (fontes de entropia `/dev/urandom` do kernel Linux).

---

### Integrante 2 (Responsável pela Fase 2: Configuração e Setup da Eleição)

#### Seções a preencher no relatório:
* **Subseção 2.3: Servidor de Votação (Administrador)** (Foco no papel durante o Setup).
* **Subseção 2.4: Autoridades Eleitorais** (Composição de $N \ge 3$ entidades).
* **Subseção 5.1: Geração Cooperativa da Chave Conjunta ($h = \prod h_i \bmod p$)**.
* **Subseção 9.4: Resposta à Questão Obrigatória (iii)** — *O que acontece se uma autoridade não participar da apuração?*

#### O que explicar em cada seção (Diretrizes técnicas):
* **Sobre a Descentralização de Confiança:** Explicar por que não existe uma "chave mestra" na mão do administrador. Justificar a exigência de $N \ge 3$ autoridades (separação de poderes inspirada em Diffie-Hellman multipartidário).
* **Sobre o Cálculo da Chave Conjunta:** Detalhar a derivação matemática:
  $$h_i = g^{x_i} \pmod p \implies h = \prod_{i=1}^N h_i \equiv g^{\sum x_i} \pmod p$$
  Mostrar que a chave privada conjunta é $x_{total} = \sum x_i$, mas **ninguém a conhece** de forma centralizada.
* **Sobre o Cadastro Prévio de Eleitores:** Detalhar a criação da Lista de Elegibilidade e por que o servidor só armazena as chaves *públicas* RSA dos eleitores.
* **Resposta à Questão (iii):** Provar matematicamente que a ausência de uma autoridade deixa um fator $g^{R \cdot x_{faltante}}$ preso na cifra, transformando a tentativa de decifração em ruído aleatório e impedindo a apuração.

---

### Integrante 3 (Responsável pela Fase 3: Sistema de Votação e Quadro Público)

#### Seções a preencher no relatório:
* **Subseção 2.2: Eleitores (Cliente)** (Geração do vetor de votos e assinatura).
* **Subseção 2.5: Quadro Público (*Bulletin Board*)** (Estrutura e imutabilidade).
* **Seção 6: Integridade do Quadro Público e Autenticação dos Eleitores**
  * `6.1` Estrutura *Append-Only* e Hash Encadeado (SHA-256).
  * `6.2` Serialização Canônica (`json.dumps` com ordenação de chaves e sem espaços).
  * `6.3` Autenticação, Assinaturas Digitais RSA e Não-Repúdio.
* **Subseção 7.1: Verificação Individual do Voto pelo Eleitor (Recibo Assinado)**.
* **Subseção 9.5: Resposta à Questão Obrigatória (iv)** — *Se o recibo permite a um eleitor provar a terceiros em quem votou*.

#### O que explicar em cada seção (Diretrizes técnicas):
* **Sobre o Vetor de Votos:** Explicar por que votamos com vetor binário $[0, 1, 0]$ e não com o ID do candidato (necessário para a soma homomórfica por candidato).
* **Sobre a Cifragem Probabilística:** Explicar o papel do fator aleatório $r$ sorteado a cada cifra. Mostrar que dois eleitores que votam no mesmo candidato geram cifras completamente distintas, impedindo correlação ou espionagem visual.
* **Sobre o Hash Encadeado:** Apresentar a fórmula da cadeia de blocos:
  $$\text{hash\_atual}_k = \text{SHA-256}(\text{hash\_atual}_{k-1} + \text{serializar\_canonico}(\text{dados}_k))$$
  Mostrar por que qualquer alteração pretérita invalida todos os hashes subsequentes.
* **Sobre a Serialização Canônica:** Enfatizar a armadilha clássica da serialização em dicionários (ordem imprevisível de chaves que quebraria assinaturas e hashes) e como `sort_keys=True` resolveu isso.
* **Resposta à Questão (iv):** Demonstrar que o recibo contém apenas $\{\text{id}, \text{indice}, \text{hash\_bloco}, \text{timestamp}\}$ assinado pelo servidor. O recibo prova que o eleitor votou (verificabilidade individual), mas **não prova em quem votou**, blindando o sistema contra compra de votos e coerção.

---

### Integrante 4 (Responsável pela Fase 4: Apuração e Decifração Distribuída)

#### Seções a preencher no relatório:
* **Subseção 4.2: Apuração Homomórfica (Produto das Cédulas e Soma nos Expoentes)**.
* **Subseção 5.2: Decifração Parcial pelas Autoridades ($d_i = C_1^{x_i} \bmod p$)**.
* **Subseção 5.3: Recombinação da Máscara Conjunta e Extração via Logaritmo Discreto**.
* **Subseção 9.2: Resposta à Questão Obrigatória (i)** — *O que acontece se um eleitor cifrar um valor diferente de 0 ou 1?*
* **Subseção 9.3: Resposta à Questão Obrigatória (ii)** — *O que acontece se todas as autoridades conspirarem?*

#### O que explicar em cada seção (Diretrizes técnicas):
* **Sobre a Multiplicação Homomórfica:** Demonstrar formalmente a álgebra da soma:
  $$C_1 = \prod_{j=1}^n c_{1,j} = g^{\sum r_j} \pmod p, \quad C_2 = \prod_{j=1}^n c_{2,j} = g^{\sum m_j} \cdot h^{\sum r_j} \pmod p$$
* **Sobre as Decifrações Parciais:** Explicar por que calcular $d_i = C_1^{x_i} \pmod p$ não revela $x_i$ (dificuldade do logaritmo discreto com expoente de 2048 bits).
* **Sobre a Recombinação da Máscara:** Mostrar como $S = \prod d_i \equiv h^{R_{total}} \pmod p$ e como $C_2 \cdot S^{-1} \equiv g^M \pmod p$.
* **Sobre a Busca do Logaritmo Discreto:** Explicar por que a força bruta é eficiente para $M \in [0, N_{eleitores}]$, mas segura contra adversários externos.
* **Resposta à Questão (i):** Explicar que sem *Provas de Conhecimento Zero (ZKP)*, a cifra aceita valores inválidos (ex: $m = 10$). Se a soma total estourar o número máximo de eleitores, a função de busca exaustiva detecta o erro e aborta; contudo, se a soma permanecer dentro da faixa, a contagem é corrompida. Indicar como limitação da solução.
* **Resposta à Questão (ii):** Explicar que se 100% das autoridades conspirarem, elas podem somar seus segredos ($x_{total} = \sum x_i$) e usar a chave privada conjunta para decifrar individualmente cada cédula do Quadro Público, violando o sigilo dos votos.

---

### Integrante 5 (Responsável pela Fase 5: Auditoria Independente e Interface CLI)

#### Seções a preencher no relatório:
* **Subseção 2.6: Auditor Independente** (Papel do observador externo e separação de privilégios).
* **Subseção 7.2: Procedimento de Verificação pelo Auditor Independente Universal**.
* **Seção 11: Instruções para Compilação e Execução** (Passo a passo reprodutível, ambiente virtual, dependências e comandos).
* **Auxílio na Seção 9.1:** Detalhamento do requisito de **Auditabilidade Universal**.

#### O que explicar em cada seção (Diretrizes técnicas):
* **Sobre a Independência do Auditor:** Enfatizar que o Auditor é um script 100% separado do Servidor, operando exclusivamente sobre o arquivo público `quadro_publico.json` sem acessar variáveis internas ou segredos.
* **Sobre o Algoritmo de Auditoria:** Detalhar a rotina de validação em 5 etapas:
  1. Recalcular e conferir o `hash_genesis` a partir da configuração da eleição.
  2. Verificar toda a cadeia de hashes do bloco 0 ao bloco $N-1$.
  3. Validar a assinatura digital RSA de cada eleitor sobre sua cédula.
  4. Conferir a elegibilidade (chaves homologadas) e unicidade (nenhum ID duplicado).
  5. Multiplicar as cédulas de forma independente para conferir a contagem homomórfica reportada.
* **Sobre as Instruções de Execução:** Documentar comandos exatos para Linux/Ubuntu: criação do `venv`, instalação de `requirements.txt` e execução da CLI/scripts de teste.

---

## Seções a Serem Escritas em Conjunto por Todos os Integrantes

As seções a seguir exigem consenso e visão unificada do projeto. Recomenda-se realizar uma reunião rápida (presencial ou online) para rascunhar os tópicos antes de redigi-los:

---

### 1. Seção 1: Introdução e Visão Geral do Sistema
* **Objetivo:** Apresentar a motivação do trabalho, o contexto da disciplina de Criptografia e a proposta de uma arquitetura descentralizada de votação.
* **O que definir juntos:** O escopo da eleição simulada (candidatos, perfil de eleitores) e a tese central: segurança baseada em matemática, e não na confiança em uma autoridade central.

---

### 2. Seção 3: Modelo de Ameaças
* **Objetivo:** Mapear quais adversários o sistema considera e o que cada um consegue ou não fazer.
* **O que discutir e preencher juntos:**
  * **3.1 Administrador/Servidor Malicioso:** Pode tentar registrar votos falsos, alterar votos existentes, omitir cédulas ou decifrar votos individuais. Mostrar como o sistema impede cada uma dessas tentativas (assinaturas RSA barram falsificação; hash encadeado barra alteração/omissão; ausência de chave privada barra decifração).
  * **3.2 Autoridade Eleitoral Desonesta:** Pode tentar decifrar votos sozinha ou recusar-se a enviar sua fatia. Mostrar como $N \ge 3$ impede decifração unilateral.
  * **3.3 Eleitor Desonesto:** Pode tentar votar duas vezes, votar no lugar de outro eleitor ou enviar cédula adulterada. Mostrar como o controle de unicidade e as chaves RSA barram essas ações.
  * **3.4 Observador da Rede (*Eavesdropper*):** Pode tentar espionar pacotes na rede ou forjar dados. Mostrar o papel de cifras probabilísticas e assinaturas digitais.

---

### 3. Subseção 9.1: Atendimento aos Requisitos Mínimos de Segurança
* **Objetivo:** Fazer um checklist analítico provando como o sistema satisfaz as 7 propriedades fundamentais:
  1. **Sigilo do Voto:** Cifragem ElGamal Exponencial probabilística + segredo compartilhado.
  2. **Integridade:** Encadeamento criptográfico SHA-256 + assinaturas RSA.
  3. **Elegibilidade:** Lista de chaves RSA pré-homologadas no setup.
  4. **Unicidade:** Flag e barreira no servidor bloqueando voto duplo.
  5. **Justiça (*Fairness*):** Bloqueio de resultados parciais antes do envio cooperativo de todos os $d_i$.
  6. **Verificabilidade Individual:** Recibo assinado com hash do bloco conferível no Quadro.
  7. **Auditabilidade Universal:** Auditor independente que valida a eleição usando apenas dados públicos.

---

### 4. Seção 10: Principais Dificuldades Encontradas e Aprendizados Obtidos
* **Objetivo:** Relato sincero e técnico sobre os desafios enfrentados durante o desenvolvimento.
* **O que reunir:** Cada integrante deve escrever 1 ou 2 parágrafos com sua principal dificuldade e aprendizado pessoal:
  * *Integrante 1:* Manipulação de números inteiros de 2048 bits e inverso modular.
  * *Integrante 2:* Sincronização dos fragmentos de chave e consistência matemática de $h$.
  * *Integrante 3:* Serialização canônica JSON e preservação de tipos de dados nos hashes.
  * *Integrante 4:* Reconstrução distribuída da máscara homomórfica e depuração do logaritmo discreto.
  * *Integrante 5:* Garantir que o auditor funcione de maneira 100% autônoma e desacoplada.

---

### 5. Revisão Final e Limite de Páginas (Todos)
* **Limite estrito:** O relatório não pode ultrapassar **10 páginas**.
* **Tarefas de fechamento:**
  * Checagem ortográfica e fluidez do texto.
  * Padronização de notação matemática ($p, g, h, r, m, c_1, c_2, C_1, C_2, d_i$).
  * Garantir que todas as 4 perguntas obrigatórias do professor estejam respondidas com clareza cristalina.
  * Conversão de [docs/relatorio_temporario.md](file:///home/alan/sistema-votacao-criptografia/docs/relatorio_temporario.md) para o arquivo final em LaTeX (`relatorio.tex` / PDF).

---