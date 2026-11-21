# Relatório Técnico: Sistema de Votação Eletrônica Seguro

**Disciplina:** Segurança Computacional  
**Professor:** Roberto Filho  
**Integrantes do Grupo:**
- Alan dos Santos Dias - 232007830
- Enzo Cardoso Martins - 242010033
- Felipe Lauterjung Caselli - 241032401
- Leandro Souza da Silva - 211031109
- Rafael Medeiros de Alencar - 241020760

**Data:** Novembro de 2026

*ElGamal Exponencial, Chave Conjunta, Quadro Público e Auditoria Independente*

---

## 1. Introdução e Visão Geral do Sistema

Este trabalho projeta e implementa, em Python, um sistema de votação eletrônica que conduz uma eleição completa (configuração, cadastro, votação, encerramento, apuração e auditoria) sem exigir confiança em nenhuma entidade isolada, nem no administrador. A tese central é que a segurança vem da matemática e não de uma autoridade central: o voto é cifrado com *ElGamal exponencial*, a chave de decifração é dividida entre $N \ge 3$ autoridades e nunca existe inteira em lugar algum, as cédulas ficam num *quadro público* encadeado por SHA-256 e assinadas com RSA, e um auditor independente verifica tudo a partir de dados públicos.

A eleição simulada tem 3 candidatos (Alice, Bob, Carol), 3 autoridades e 5 eleitores cadastrados. Só usamos primitivas básicas: aritmética modular de Python (`pow`), `hashlib`, `secrets` e a biblioteca `cryptography` apenas para RSA. O ElGamal, a chave conjunta, a apuração homomórfica e o quadro público foram implementados por nós, como exige o enunciado.

---

## 2. Arquitetura e Responsabilidades

### 2.1 Visão geral

O sistema tem cinco entidades. Nenhuma delas, sozinha, consegue ler um voto individual nem alterar o resultado sem ser detectada.

```text
                 cédula cifrada + assinatura RSA              C1 / h_i
   ┌──────────┐ ─────────────────────────────────▶ ┌────────────┐ ─────────────▶ ┌─────────────┐
   │ Eleitor  │                                    │ Servidor   │                │ Autoridades │
   │ (cliente)│ ◀ ─ ─ ─ ─ ─ recibo assinado ─ ─ ─ ─│ de votação │ ◀ ─ ─ d_i ─ ─ ─│   (N ≥ 3)   │
   └──────────┘                                    └─────┬──────┘  d_i = C1^x_i  └─────────────┘
                                                         │ append
                                                         ▼
                                                  ┌────────────┐   lê (só dados   ┌─────────────┐
                                                  │  Quadro    │ ───────────────▶ │  Auditor    │
                                                  │  Público   │     públicos)    │ independente│
                                                  └────────────┘                  └─────────────┘
```

### 2.2 Eleitores (cliente) — `votacao.py`

Cada eleitor possui um par RSA cadastrado antes da votação. O cliente monta o *vetor de votos* (1 na posição do candidato escolhido, 0 nas demais), cifra cada posição com um $r$ novo, serializa $\{\text{id}, \text{cédula}\}$ em JSON canônico, assina com RSA-PSS e envia o pacote. Ao receber o recibo, confere a assinatura do servidor.

### 2.3 Servidor de votação (administrador) — `setup_eleicao.py`, `votacao.py`

No setup, recebe as chaves parciais $h_i$ e calcula $h = \prod h_i \bmod p$. Guarda apenas as chaves *públicas* RSA dos eleitores. Na votação, valida cada pacote (formato, elegibilidade, unicidade, assinatura), anexa o bloco ao quadro e emite o recibo assinado. Na apuração, multiplica as cifras e combina as decifrações parciais. Ele **não** possui nenhuma parcela de $x$ e, portanto, não decifra nada.

### 2.4 Autoridades eleitorais — `setup_eleicao.py`, `apuracao.py`

São $N \ge 3$ entidades independentes. Cada uma gera $x_i$ (que nunca sai de sua posse), publica $h_i = g^{x_i}$ e, na apuração, devolve $d_i = C_1^{x_i}$ para cada candidato.

### 2.5 Quadro público — `votacao.py`

Arquivo JSON somente de acréscimo. Contém a configuração pública da eleição ($p$, $g$, $h$, os $h_i$, candidatos, chave pública do servidor, lista de eleitores com suas chaves públicas), o `hash_genesis` e a lista de blocos (id do eleitor, cédula cifrada, assinatura, instante, hash anterior e hash atual).

### 2.6 Auditor independente — `auditor.py`

Programa separado do servidor, que lê *somente* `quadro_publico.json`. Não acessa segredos nem o estado interno do servidor (detalhes na Seção 7.2).

---

## 3. Modelo de Ameaças

| Adversário | O que consegue tentar | Contramedida e limite |
|---|---|---|
| **Administrador / servidor malicioso** | Forjar cédulas; alterar, remover ou reordenar cédulas; votar por eleitores que não votaram; decifrar votos; recusar cédulas. | Forjar exige a chave RSA do eleitor. Alterar/reordenar quebra o encadeamento e a assinatura. Não tem $x_i$, logo não decifra. *Limite:* pode censurar uma cédula antes de aceitá-la (o eleitor percebe por não receber recibo) e pode cortar as *últimas* cédulas sem quebrar a cadeia (só quem tem recibo percebe, pois seu `hash_bloco` sumiria do quadro). |
| **Autoridade desonesta** | Decifrar sozinha; recusar-se a participar; enviar $d_i$ falso. | Um único $x_i$ não decifra nada. Recusa ou $d_i$ falso fazem a apuração falhar (testado na demo), sem produzir resultado errado. *Limite:* a falha não aponta o culpado (não há prova de decifração correta) e o esquema é $N$-de-$N$ (Seção 9.4). |
| **Eleitor desonesto** | Votar duas vezes; votar por outro; enviar cédula malformada ou com valor $\ne 0,1$; provar o voto a terceiros. | Unicidade e assinatura RSA barram os dois primeiros; checagem de formato barra a malformada. *Limite:* sem prova de conhecimento zero, valores $\ne 0,1$ não são detectados (Seção 9.2); recibo (Seção 9.5). |
| **Observador da rede** | Ler pacotes; modificar ou reenviar cédulas. | Só vê cifras probabilísticas (nada sobre o voto). Modificar invalida a assinatura; reenviar esbarra na unicidade. *Limite:* a simulação roda em um processo, sem TLS; quem votou (o id) é público, apenas o conteúdo é secreto. |

---

## 4. Cifragem dos Votos e Apuração Homomórfica

### 4.1 ElGamal exponencial vetorial

Sejam $p$ primo, $g$ gerador e $h$ a chave pública conjunta. Para cada candidato $k$, o eleitor escolhe $m_k \in \{0,1\}$ (1 só para o escolhido), sorteia $r_k$ com `secrets` e produz

$$(c_{1,k}, c_{2,k}) = \bigl(g^{r_k} \bmod p,\; g^{m_k}\, h^{r_k} \bmod p\bigr).$$

Como $r_k$ é novo a cada cifra, dois eleitores com o mesmo voto geram cifras completamente distintas, e as posições 0 e 1 da mesma cédula são indistinguíveis para quem não conhece $x$ (segurança semântica sob DDH). O vetor binário, em vez do id do candidato, é o que permite somar por candidato.

### 4.2 Apuração sem decifrar votos individuais

Para cada candidato, o servidor multiplica as cifras de todas as $n$ cédulas:

$$C_1 = \prod_{j=1}^{n} c_{1,j} = g^{R}, \qquad C_2 = \prod_{j=1}^{n} c_{2,j} = g^{M}\, h^{R}, \qquad R = \sum_j r_j,\; M = \sum_j m_j.$$

$M$ é o total de votos do candidato, e $h^R$ é a máscara que impede ler $g^M$. Nenhuma cédula individual é decifrada: só o agregado.

---

## 5. Chave Conjunta e Decifração Distribuída

### 5.1 Geração cooperativa da chave

Cada autoridade $i$ sorteia $x_i$ e publica $h_i = g^{x_i} \bmod p$. O servidor calcula

$$h = \prod_{i=1}^{N} h_i = g^{\sum_i x_i} \bmod p,$$

ou seja, a chave privada conjunta é $x = \sum_i x_i$, mas **ninguém a conhece** (cada $x_i$ fica só com sua autoridade). Não há chave mestra com o administrador.

### 5.2 Decifração parcial

O servidor envia o valor público $C_1$ de cada candidato. A autoridade $i$ devolve $d_i = C_1^{x_i} \bmod p$. Obter $x_i$ a partir de $(C_1, d_i)$ equivale a calcular um logaritmo discreto em um grupo de 2048 bits, inviável.

### 5.3 Recombinação e extração

O servidor calcula

$$S = \prod_{i=1}^{N} d_i = C_1^{\sum x_i} = g^{R x} = h^{R}, \qquad C_2 \cdot S^{-1} \bmod p = g^{M}.$$

Para obter $M$ testamos $g^0, g^1, \dots, g^n$ até coincidir (`decifrar_logaritmo_discreto`). A busca exaustiva é viável porque $M \le n$ (número de eleitores), e inofensiva porque só se aplica ao total, nunca a uma cédula.

---

## 6. Integridade do Quadro e Autenticação dos Eleitores

### 6.1 Estrutura *append-only* e hash encadeado

O quadro nasce com $H_0 = \text{SHA-256}(\text{config. canônica})$, que o amarra aos parâmetros da eleição. Cada bloco $k$ (dados $D_k$: índice, id, chave pública, cédula, assinatura, instante) recebe

$$H_k = \text{SHA-256}\bigl(H_{k-1} \,\Vert\, \text{canônico}(D_k)\bigr),$$

e guarda $H_{k-1}$ e $H_k$. Alterar, remover ou reordenar qualquer bloco muda seu hash e invalida todos os seguintes. A única operação de escrita do quadro é `adicionar_bloco`, que apenas acrescenta no fim.

### 6.2 Serialização canônica

Hash e assinatura dependem de bytes idênticos em quem assina e em quem verifica. Usamos `json.dumps(sort_keys=True, separators=(',',':'))`: sem isso, a ordem das chaves do dicionário ou espaços diferentes quebrariam hashes e assinaturas. Os números grandes são mantidos como inteiros, para que o mesmo valor gere sempre o mesmo texto.

### 6.3 Autenticação e não-repúdio

O eleitor assina $\{\text{id}, \text{cédula}\}$ com RSA-2048, padding PSS e SHA-256. A assinatura vai no quadro, portanto qualquer pessoa verifica, com a chave pública registrada na configuração, que aquela cédula foi emitida por aquele eleitor e não foi alterada; o eleitor não pode negar tê-la enviado. O servidor assina, com sua própria chave RSA, o recibo de cada voto.

---

## 7. Auditoria e Verificação Individual

### 7.1 Verificação individual (recibo)

O recibo contém $\{\text{id}, \text{índice}, \text{hash\_bloco}, \text{instante}\}$ assinado pelo servidor. O eleitor confere (comando `verificar-recibo`) que (i) a assinatura do servidor é válida e (ii) o bloco de mesmo índice no quadro público tem o mesmo `hash_bloco` e o seu id. Se o servidor tivesse descartado ou trocado a cédula, o recibo não bateria com o quadro.

### 7.2 Auditor independente universal

O auditor lê só `quadro_publico.json` e executa:

1. recálculo do `hash_genesis`;
2. verificação da cadeia de hashes do primeiro ao último bloco;
3. verificação da assinatura RSA de cada eleitor sobre sua cédula;
4. elegibilidade (todo id consta na lista cadastrada);
5. unicidade (nenhum id repetido);
6. formato das cédulas (uma cifra por candidato, valores em $[1, p-1]$);
7. recálculo independente do produto homomórfico $(C_1, C_2)$ de cada candidato.

A *independência* é de dados e de privilégios: não recebe segredos, não consulta o estado do servidor e não decifra nada, embora reutilize funções utilitárias do repositório (hash, verificação RSA, serialização). Na demonstração, alterar uma única cifra de um bloco faz falharem a cadeia de hashes e a assinatura do eleitor, e o auditor acusa o bloco exato.

---

## 8. Parâmetros e Algoritmos Criptográficos

| Componente | Escolha | Justificativa |
|---|---|---|
| **Grupo ElGamal** | RFC 3526 grupo 14: $p$ primo seguro de 2048 bits, $g = 2$ | $p = 2q+1$ com $q$ primo: não há subgrupos pequenos (evita Pohlig–Hellman). Como $p \equiv 7 \pmod 8$, $2$ é resíduo quadrático e gera o subgrupo de ordem $q$. 2048 bits dão cerca de 112 bits de segurança (NIST SP 800-57). Grupo padronizado é permitido pelo enunciado e evita erros de geração própria. |
| **Assinaturas** | RSA-2048, $e = 65537$, PSS (MGF1/SHA-256, sal máximo) | PSS é probabilístico e tem prova de segurança no modelo do oráculo aleatório, ao contrário do PKCS#1 v1.5. Usado por eleitores e servidor. |
| **Hash** | SHA-256 | Resistente a colisão e pré-imagem; padrão para encadeamento e para a assinatura PSS. |
| **Aleatoriedade** | `secrets` (entropia do SO) | $x_i$ e $r$ precisam ser imprevisíveis; `random` (Mersenne Twister) permitiria reconstruir o estado e prever $r$. |
| **Aritmética** | `pow(b,e,m)`, `pow(a,-1,m)` | Exponenciação modular por quadrados e multiplicações, sem estourar memória; o inverso usa Euclides estendido. |

---

## 9. Análise de Segurança

### 9.1 Requisitos mínimos

| Requisito | Como é atendido (e limite) |
|---|---|
| **Sigilo do voto** | Cifra ElGamal probabilística; sem $x$ ninguém decifra; ordem e instante não revelam nada pois as cifras são independentes do voto. *Limite:* conluio de todas as autoridades (Seção 9.3). |
| **Integridade** | Hash encadeado e assinaturas RSA. *Limite:* corte das últimas cédulas só é notado por quem tem recibo. |
| **Elegibilidade** | Chaves públicas homologadas na configuração; servidor e auditor conferem. |
| **Unicidade** | Servidor recusa id que já votou; auditor confere ids repetidos. |
| **Justiça** | Resultado parcial exige $d_i$ de *todas* as autoridades, e a CLI só apura após `encerrar`. *Limite:* depende de as autoridades não fornecerem $d_i$ antes do fim. |
| **Verificabilidade individual** | Recibo assinado, conferível contra o quadro. |
| **Auditabilidade** | Auditor independente, só com dados públicos (Seção 7.2). |

### 9.2 (i) Eleitor cifra um valor diferente de 0 ou 1

O sistema *não* impede isso: o servidor só vê $(c_1, c_2)$ e não consegue saber o $m$ dentro da cifra, e não há prova de conhecimento zero (ZKP) de que $m \in \{0,1\}$. Se um eleitor cifra $m = 10$ (ou $m = -1$, ou vários 1 na mesma cédula), o total do candidato fica corrompido. Se a soma passa do número de cédulas, a busca exaustiva falha e a apuração aborta (um único eleitor desonesto consegue travar a contagem); se a soma ainda cabe na faixa, a fraude *passa despercebida*. É a principal limitação da solução. A correção seria exigir, em cada posição, uma prova disjuntiva de Chaum–Pedersen de que $m \in \{0,1\}$, e uma prova de que a soma da cédula é 1; não a implementamos.

### 9.3 (ii) Todas as autoridades conspiram

O sigilo cai. Elas somam os segredos, $x = \sum_i x_i$, e decifram *cada cédula* do quadro, que é público: $g^{m} = c_2 \cdot (c_1^{x})^{-1}$, com $m \in \{0,1\}$ trivial de ler. Isso mostra o preço do modelo: o sigilo exige que *pelo menos uma* autoridade seja honesta. Um subconjunto estrito não basta, pois falta $c_1^{x_k}$ da autoridade excluída.

### 9.4 (iii) Uma autoridade não participa da apuração

Sem $d_k$, o servidor obtém $S' = \prod_{i \ne k} d_i = h^R / C_1^{x_k}$ e, portanto, $C_2 \cdot S'^{-1} = g^{M}\, C_1^{x_k} = g^{M + R x_k}$, que parece um elemento aleatório do grupo. A chance de coincidir com algum $g^0, \dots, g^n$ é desprezível, então a busca falha e *nenhum resultado é divulgado* (demonstrado na CLI com `apurar --sem-autoridade 3`). O custo é de disponibilidade: o esquema é $N$-de-$N$, e uma só autoridade ausente bloqueia a eleição. Um esquema limiar (compartilhamento de Shamir) resolveria, ao custo de maior complexidade.

### 9.5 (iv) O recibo permite provar a terceiros em quem se votou?

Não por si só. O recibo contém apenas $\{\text{id}, \text{índice}, \text{hash\_bloco}, \text{instante}\}$, assinado pelo servidor; não traz o voto, a cédula nem o $r$. Ele prova *que* a cédula foi registrada, não *em quem* se votou, o que dificulta compra de votos e coerção. Há uma ressalva honesta: o cliente gera $r$ e o descarta, mas um cliente modificado poderia guardá-lo. Com $(m, r)$ qualquer um verifica $c_1 = g^r$ e $c_2\, g^{-m} = h^r$, e o voto é provado. Logo o sistema não é *à prova de coerção*; isso exigiria, por exemplo, recifragem ou voto revogável.

### 9.6 Outras limitações

- **(a)** Não há prova de conhecimento de $x_i$: a última autoridade a publicar poderia escolher $h_N = Y \cdot (\prod_{i<N} h_i)^{-1}$ e passar a ser a única a conhecer a chave conjunta; mitigaríamos com provas de Schnorr ou *commit–reveal* no setup.
- **(b)** Não há prova de que $d_i$ foi calculado corretamente (Chaum–Pedersen), então uma autoridade que sabota só é detectada pela falha, sem ser identificada.
- **(c)** O cadastro gera as chaves dos eleitores (simulação); na prática cada eleitor geraria a sua.
- **(d)** O resultado final não é publicado com provas, portanto o auditor valida $C_1, C_2$, mas não confirma $M$ sozinho.

---

## 10. Principais Dificuldades Encontradas e Aprendizados Obtidos

**Aritmética com inteiros de 2048 bits.** Entender por que `pow(b,e,m)` resolve o que `(b**e)%m` não resolve (memória) e usar o inverso modular em vez de "dividir". Aprendizado: a divisão no grupo é multiplicar por $a^{-1}$.

**Consistência da chave conjunta.** Garantir que $h = g^{\sum x_i}$ de fato bata com os segredos distintos de cada autoridade, e que nenhuma delas reaparecesse duas vezes. Aprendizado: a descentralização da confiança é só aritmética de expoentes.

**Serialização canônica.** Hash e assinatura quebravam quando a ordem das chaves ou o tipo dos números (inteiro × texto) mudava entre quem assina e quem verifica. Aprendizado: segurança criptográfica depende de bytes idênticos.

**Reconstrução da máscara e depuração do logaritmo discreto.** Quando $S$ está errado, o resultado não é "um pouco errado", é aleatório e a busca simplesmente não acha. Aprendizado: foi esse comportamento que nos deu a resposta da pergunta (iii).

**Auditor desacoplado.** Fazer o auditor funcionar só com o arquivo público, sem consultar o servidor. Aprendizado: o que se quer verificável precisa estar no quadro (por isso a configuração com as chaves dos eleitores está no `hash_genesis`).

---

## 11. Instruções para Compilação e Execução

Requer Python 3.9+ (Linux/Ubuntu). A partir da raiz do projeto:

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt          # cryptography
python3 src/cli.py demo                  # roteiro completo da apresentação
```

O `demo` executa: eleição com 3 autoridades e 5 eleitores; voto duplo rejeitado; adulteração de uma cédula detectada pelo auditor; apuração sem uma autoridade (falha); apuração final. Comandos individuais (`setup`, `votar`, `verificar-recibo`, `encerrar`, `adulterar`, `auditar`, `apurar [--sem-autoridade N]`, `status`) estão no `README.md`. O auditor também roda sozinho: `python3 src/auditor.py eleicao/publico/quadro_publico.json`.
