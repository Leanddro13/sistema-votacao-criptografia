# Relatório Técnico: Sistema de Votação Eletrônica Seguro

**Disciplina:** Segurança Computacional  
**Professor:**  Roberto Filho
**Integrantes do Grupo:**  
- Alan dos Santos Dias - 232007830
- Integrante 2 (Matrícula)
- Integrante 3 (Matrícula)
- Integrante 4 (Matrícula)  
- Integrante 5 (Matrícula)  
**Data:** Novembro de 2026  

---

## 1. Introdução e Visão Geral do Sistema

<!-- A preencher -->

---

## 2. Descrição Completa da Arquitetura e Responsabilidades

### 2.1 Visão Geral da Arquitetura
<!-- A preencher -->

### 2.2 Eleitores (Cliente)
<!-- A preencher -->

### 2.3 Servidor de Votação (Administrador)
<!-- A preencher -->

### 2.4 Autoridades Eleitorais
<!-- A preencher -->

### 2.5 Quadro Público (*Bulletin Board*)
<!-- A preencher -->

### 2.6 Auditor Independente
<!-- A preencher -->

---

## 3. Modelo de Ameaças

### 3.1 Administrador / Servidor Malicioso
<!-- A preencher -->

### 3.2 Autoridade(s) Eleitoral(is) Desonesta(s)
<!-- A preencher -->

### 3.3 Eleitor Desonesto
<!-- A preencher -->

### 3.4 Observador da Rede (Ataques Passivos e Ativos)
<!-- A preencher -->

---

## 4. Esquema de Cifragem e Apuração Homomórfica

### 4.1 Cifragem ElGamal Exponencial Vetorial
<!-- A preencher -->

### 4.2 Apuração Homomórfica (Produto das Cédulas e Soma nos Expoentes)
<!-- A preencher -->

---

## 5. Chave Pública Conjunta e Decifração Distribuída

### 5.1 Geração Cooperativa da Chave Conjunta ($h = \prod h_i \bmod p$)
<!-- A preencher -->

### 5.2 Decifração Parcial pelas Autoridades ($d_i = C_1^{x_i} \bmod p$)
<!-- A preencher -->

### 5.3 Recombinação da Máscara Conjunta e Extração via Logaritmo Discreto
<!-- A preencher -->

---

## 6. Integridade do Quadro Público e Autenticação dos Eleitores

### 6.1 Estrutura *Append-Only* e Hash Encadeado (SHA-256)
<!-- A preencher -->

### 6.2 Serialização Canônica
<!-- A preencher -->

### 6.3 Autenticação, Assinaturas Digitais RSA e Não-Repúdio
<!-- A preencher -->

---

## 7. Procedimento de Auditoria e Verificação Individual

### 7.1 Verificação Individual do Voto pelo Eleitor (Recibo Assinado)
<!-- A preencher -->

### 7.2 Procedimento de Verificação pelo Auditor Independente Universal
<!-- A preencher -->

---

## 8. Parâmetros e Algoritmos Criptográficos

### 8.1 Grupo Cíclico e Parâmetros (RFC 3526 MODP - 2048 bits) e Justificativa
<!-- A preencher -->

### 8.2 Assinaturas RSA (2048 bits com PSS/SHA-256) e Justificativa
<!-- A preencher -->

### 8.3 Função Hash (SHA-256) e Justificativa
<!-- A preencher -->

### 8.4 Gerador de Números Aleatórios Criptograficamente Seguro (`secrets`)
<!-- A preencher -->

---

## 9. Análise de Segurança e Respostas às Questões Críticas

### 9.1 Atendimento aos Requisitos Mínimos de Segurança
* **Sigilo do Voto:** <!-- A preencher -->
* **Integridade:** <!-- A preencher -->
* **Elegibilidade:** <!-- A preencher -->
* **Unicidade:** <!-- A preencher -->
* **Justiça (*Fairness*):** <!-- A preencher -->
* **Verificabilidade Individual:** <!-- A preencher -->
* **Auditabilidade Universal:** <!-- A preencher -->

### 9.2 Questão Obrigatória (i): Cifragem de valor diferente de 0 ou 1
<!-- A preencher -->

### 9.3 Questão Obrigatória (ii): Conluio de todas as autoridades
<!-- A preencher -->

### 9.4 Questão Obrigatória (iii): Não participação de uma autoridade na apuração
<!-- A preencher -->

### 9.5 Questão Obrigatória (iv): Propriedades do recibo e coerção/venda de voto
<!-- A preencher -->

---

## 10. Principais Dificuldades Encontradas e Aprendizados Obtidos

### 10.1 Principais Dificuldades Encontradas
<!-- A preencher -->

### 10.2 Aprendizados Obtidos
<!-- A preencher -->

---

## 11. Instruções para Compilação e Execução
<!-- A preencher -->
