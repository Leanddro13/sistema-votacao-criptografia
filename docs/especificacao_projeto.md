# Especificação do Projeto: Sistema de Votação Eletrônica Seguro

**Disciplina:** Criptografia  
**Prazo de Entrega (Aprender3):** 23/11/2026  
**Apresentações Presenciais:** 25/11/2026, 30/11/2026 e 07/12/2026  
**Formato de Grupo:** Até 5 integrantes  

---

## 1. Visão Geral e Objetivo

O presente trabalho tem como objetivo o projeto e a implementação de um **sistema de votação eletrônica seguro**, aplicando os conceitos fundamentais vistos na disciplina:
- **ElGamal Exponencial** (com propriedades homomórficas aditivas)
- **Compartilhamento e Chave Conjunta** (baseado em Diffie-Hellman multipartidário)
- **RSA** e **Assinaturas Digitais**
- **Funções Hash Criptográficas (SHA-256)**

O sistema deve conduzir uma eleição completa — cobrindo desde o cadastro dos eleitores, setup das autoridades, coleta de votos, até a apuração homomórfica e auditoria independente —, garantindo propriedades formais de segurança mesmo diante de participantes maliciosos, inclusive o próprio administrador do sistema.

---

## 2. Requisitos de Entrega e Critérios de Avaliação

A avaliação totaliza **10,0 pontos**, distribuídos em quatro eixos:

### 2.1 Código Completo da Aplicação (3,5 pontos)
- **Cifragem dos votos e apuração homomórfica corretas (1,0 ponto):** Cifragem vetorial com ElGamal exponencial e produto homomórfico das cédulas sem decifração individual.
- **Geração da chave conjunta e decifração pelas autoridades (0,75 ponto):** Setup com $N \ge 3$ autoridades, derivação de $h = \prod h_i \bmod p$ e decifração parcial cooperativa ($d_i = C_1^{x_i} \bmod p$).
- **Quadro público encadeado por hashes e detecção de adulteração (0,75 ponto):** Registro *append-only* com encadeamento SHA-256 e verificação de quebra de integridade.
- **Assinaturas, elegibilidade, unicidade e recibo do eleitor (0,5 ponto):** Assinatura RSA do eleitor, conferência de chave pré-cadastrada, bloqueio de voto duplo e emissão de recibo assinado pelo servidor.
- **Programa auditor independente (0,5 ponto):** Script/aplicação separada que audita toda a eleição usando exclusivamente dados públicos.

### 2.2 Instruções de Compilação e Execução (0,5 ponto)
- Instruções claras, reprodutíveis e documentadas no `README.md` para preparação do ambiente, instalação de dependências e execução de todas as etapas.

### 2.3 Relatório Técnico — Máximo de 10 páginas (3,0 pontos)
O relatório técnico deverá conter obrigatoriamente:
1. **Descrição Completa da Arquitetura:** Todas as entidades (Eleitores, Servidor de Votação, Autoridades Eleitorais, Quadro Público e Auditor) e suas respectivas responsabilidades.
2. **Modelo de Ameaças:** Adversários considerados (administrador malicioso, autoridade desonesta, eleitor desonesto, observador da rede) e as capacidades/limitações de cada um.
3. **Esquema de Cifragem e Apuração Homomórfica:** Detalhamento matemático de como os votos são cifrados e como a apuração obtém o total sem revelar os votos individuais.
4. **Chave Conjunta e Decifração Distribuída:** Como $h$ é gerada e como as autoridades colaboram na decifração do resultado final.
5. **Integridade do Quadro Público e Autenticação:** Detalhamento do hash encadeado (SHA-256) e das assinaturas digitais RSA.
6. **Auditoria e Verificação Individual:** Procedimentos do auditor independente e funcionamento do recibo emitido ao eleitor.
7. **Parâmetros e Algoritmos Criptográficos:** Grupo cíclico (primo $\ge 2048$ bits, gerador $g$), chaves RSA 2048 bits, SHA-256 e justificativas formais de escolha.
8. **Análise de Segurança e Limitações da Solução (Obrigatório responder):**
   - *(i)* O que acontece se um eleitor cifrar um valor diferente de 0 ou 1?
   - *(ii)* O que acontece se todas as autoridades conspirarem?
   - *(iii)* O que acontece se uma autoridade não participar da apuração?
   - *(iv)* Se o recibo permite a um eleitor provar a terceiros em quem votou (análise de coerção e venda de voto).
9. **Dificuldades e Aprendizados:** Relato das principais barreiras encontradas durante a implementação e lições aprendidas.

### 2.4 Apresentação Presencial e Arguição (3,0 pontos)
- **Tempo:** 10 minutos de apresentação e demonstração ao vivo + até 10 minutos de arguição individual pelo professor.
- **Participação:** Todos os integrantes devem apresentar ativamente e estar preparados para perguntas individuais (as notas individuais podem divergir).
- **Roteiro Obrigatório da Demonstração ao Vivo:**
  1. Realização de uma eleição completa com pelo menos 3 eleitores e 3 autoridades eleitorais;
  2. Tentativa de um eleitor votar duas vezes (demonstrando a rejeição e bloqueio);
  3. Adulteração proposital de uma cédula no Quadro Público (demonstrando a detecção imediata pelo programa auditor);
  4. Tentativa de apuração sem a participação de todas as autoridades (demonstrando a falha e impossibilidade de decifrar o resultado).

---

## 3. Arquitetura Obrigatória

A solução deve ser implementada com base nos seguintes pilares criptográficos:

1. **ElGamal Exponencial:**
   - Cada voto $m \in \{0, 1\}$ é cifrado como:
     $$(c_1, c_2) = (g^r \bmod p,\; g^m \cdot h^r \bmod p)$$
   - Para uma eleição com $K$ candidatos, o eleitor envia um vetor de cifras: $1$ para o candidato escolhido e $0$ para os demais.
   - A apuração multiplica os pares $(c_1, c_2)$ de todos os votos para cada candidato, resultando em:
     $$(C_1, C_2) = \left(\prod c_{1,j} \bmod p,\; \prod c_{2,j} \bmod p\right) = (g^{\sum r_j} \bmod p,\; g^M \cdot h^{\sum r_j} \bmod p)$$
     onde $M$ é a soma dos votos daquele candidato, recuperada por busca do logaritmo discreto.

2. **Chave Conjunta das Autoridades ($N \ge 3$):**
   - Cada autoridade $i$ gera um segredo $x_i \in [1, p-2]$ e publica $h_i = g^{x_i} \bmod p$.
   - A chave pública da eleição é o produto das chaves parciais:
     $$h = \prod_{i=1}^N h_i \bmod p = g^{\sum x_i} \bmod p$$
   - A decifração exige a cooperação de **todas** as autoridades fornecendo $d_i = C_1^{x_i} \bmod p$. Nenhuma autoridade individual nem o administrador conhece o expoente privado total $x = \sum x_i$.

3. **Quadro Público (*Bulletin Board*):**
   - Estrutura de dados pública, serializável e somente de acréscimo (*append-only*).
   - Encadeamento criptográfico: cada bloco armazena o hash SHA-256 do bloco anterior mais a serialização canônica do bloco atual.
   - Contém: identificação pública do eleitor, cédula cifrada, assinatura digital do eleitor e hashes encadeados.

4. **Assinaturas Digitais (RSA):**
   - Chaves RSA de 2048 bits cadastradas antes da eleição.
   - O eleitor assina digitalmente seu pacote de voto.
   - O servidor valida a elegibilidade, unicidade e assinatura, e devolve ao eleitor um recibo assinado digitalmente com a chave privada do servidor.

---

## 4. Requisitos Mínimos de Segurança

| Propriedade | Descrição |
| :--- | :--- |
| **Sigilo do Voto** | Nenhuma entidade isolada (inclusive o administrador) consegue descobrir o voto individual de um eleitor, nem por correlação temporal ou ordenação. |
| **Integridade** | Nenhuma cédula registrada pode ser alterada, removida, reordenada ou inserida sem que isso seja detectado pelo encadeamento de hashes. |
| **Elegibilidade** | Somente eleitores previamente homologados e com chaves públicas cadastradas podem submeter votos. |
| **Unicidade** | Cada eleitor pode votar no máximo uma vez. Tentativas adicionais devem ser rejeitadas. |
| **Justiça (*Fairness*)** | Nenhum resultado parcial pode ser conhecido ou inferido antes do encerramento oficial da votação. |
| **Verificabilidade Individual** | O eleitor pode conferir que sua cédula foi devidamente registrada e preservada no Quadro Público por meio do seu recibo. |
| **Auditabilidade Universal** | Qualquer auditor independente, dispondo apenas dos dados públicos, pode verificar a validade de toda a eleição (cadeia de blocos, assinaturas, elegibilidade, unicidade e apuração homomórfica). |

---

## 5. Restrições e Diretrizes de Implementação

- **Proibição de Bibliotecas de Alto Nível:** Não é permitido o uso de frameworks de votação eletrônica prontos ou bibliotecas que implementem ElGamal / cifragem homomórfica.
- **Primitivas Permitidas:** Aritmética modular nativa (Python `pow(b, e, m)`), funções hash (`hashlib`), números aleatórios seguros (`secrets`) e biblioteca para assinaturas RSA (`cryptography`).
- **Tamanho dos Parâmetros:** Primos criptográficos com pelo menos 2048 bits (permitido grupo RFC 3526 MODP) e chaves RSA de 2048 bits.
- **Uso de IA:** Permitido apenas com total domínio do código por parte dos alunos; cada integrante deve ser capaz de explicar em detalhes todo o código produzido durante a arguição presencial.
- **Entrega de Arquivos:** Todos os arquivos (código, documentação, relatório) devem ser submetidos diretamente na plataforma **Aprender3** até 23/11/2026. Não serão aceitos links externos para repositórios públicos.
