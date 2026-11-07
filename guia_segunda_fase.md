# Aula 02: Configuração e Setup da Eleição (Fase 2)

Bem-vindo(a)! Se a Fase 1 foi a fabricação dos **tijolos e cadeados** (primitivas matemáticas isoladas), a Fase 2 é onde começamos a **erigir as paredes do prédio**: integramos as entidades **Autoridade** e **Servidor** para configurar a eleição antes de qualquer voto ser emitido.

Nesta fase, não vamos ainda receber votos de eleitores. Vamos apenas:

1. Fazer cada Autoridade gerar sua própria chave privada secreta $x_i$ e sua chave pública parcial $h_i = g^{x_i} \bmod p$.
2. Fazer o Servidor coletar todas as $h_i$ e calcular a chave pública conjunta $h = \prod h_i \bmod p$.
3. Cadastrar os eleitores pré-definidos, gerando pares de chaves RSA para cada um e montando a lista de elegibilidade.

---

## 🛠️ Antes de começar

Você vai continuar usando o mesmo arquivo `cripto_base.py` da Fase 1, ou criar um novo arquivo `setup_eleicao.py` que importe as funções de `cripto_base.py`. Mantenha o ambiente virtual ativado e a biblioteca `cryptography` instalada:

```bash
pip install cryptography
```

O arquivo `cripto_base.py` da Fase 1 já disponibiliza tudo o que você precisa:
- `P` e `G` (parâmetros do grupo RFC 3526)
- `gerar_numero_aleatorio_seguro(limite_maximo)` para gerar $x_i$ de forma criptograficamente segura
- `exp_mod(base, expoente, modulo)` para calcular $g^{x_i} \bmod p$
- `gerar_par_chaves_rsa()` para criar pares de chaves dos eleitores

---

## 🎯 Task 2.1: Rotina das Autoridades (chave privada $x_i$ e pública parcial $h_i$)

### O que a especificação pede?

> *"Implementar rotina das Autoridades para geração da chave privada $x_i$ e submissão da chave pública parcial $h_i$."*

### Traduzindo os termos técnicos:

* **Autoridade Eleitoral ($N \ge 3$):** Uma entidade que participa do setup da eleição. Cada autoridade tem sua própria chave privada secreta $x_i$ (nunca revelada a ninguém) e deriva dela uma chave pública parcial $h_i$.
* **Chave privada $x_i$:** Um número aleatório grande (de 2048 bits) escolhido no intervalo $[1, p-1]$. É o segredo da autoridade $i$. Sem ele, ninguém consegue decifrar nada sozinho.
* **Chave pública parcial $h_i$:** Calculada como $h_i = g^{x_i} \bmod p$. É pública — pode ser enviada ao Servidor e publicada no Quadro Público. A partir dela, ninguém consegue descobrir $x_i$ (problema do logaritmo discreto).
* **Submissão:** Cada autoridade envia seu $h_i$ ao Servidor, que irá combiná-los.

### Por que $N \ge 3$ autoridades?

O sistema é projetado para que **nenhuma autoridade sozinha** consiga decifrar os votos. Apenas quando **todas** (ou um quórum suficiente) colaborarem na fase de apuração, a máscara completa poderá ser removida. Isso evita conluio e centralização de poder.

### Implementação sugerida:

```python
# =====================================================================
# TASK 2.1: Rotina das Autoridades Eleitorais
# =====================================================================

from cripto_base import P, G, exp_mod, gerar_numero_aleatorio_seguro

class AutoridadeEleitoral:
    """
    Representa uma Autoridade Eleitoral que detém um fragmento da chave privada.
    """
    
    def __init__(self, id_autoridade: int):
        self.id = id_autoridade
        self.x_i = None  # Chave privada secreta (nunca compartilhada)
        self.h_i = None  # Chave pública parcial (enviada ao servidor)
    
    def gerar_chave_privada(self):
        """
        Gera a chave privada secreta x_i no intervalo [1, p-1].
        """
        self.x_i = gerar_numero_aleatorio_seguro(P - 1)
        return self.x_i
    
    def calcular_chave_publica_parcial(self):
        """
        Calcula a chave pública parcial h_i = g^(x_i) mod p.
        Deve ser chamada após gerar_chave_privada().
        """
        if self.x_i is None:
            raise ValueError("Chave privada x_i ainda não foi gerada!")
        
        self.h_i = exp_mod(G, self.x_i, P)
        return self.h_i
    
    def submeter_chave_publica(self):
        """
        Retorna a chave pública parcial para submissão ao Servidor.
        """
        if self.h_i is None:
            raise ValueError("Chave pública parcial h_i ainda não foi calculada!")
        
        return {
            'autoridade_id': self.id,
            'h_i': self.h_i
        }
```

### Exemplo de uso e teste:

```python
if __name__ == "__main__":
    print("=== TESTE TASK 2.1: Autoridades ===\n")
    
    # Criando 3 autoridades (N >= 3 conforme especificação)
    autoridades = [
        AutoridadeEleitoral(id_autoridade=1),
        AutoridadeEleitoral(id_autoridade=2),
        AutoridadeEleitoral(id_autoridade=3),
    ]
    
    submissoes = []
    
    for auth in autoridades:
        # Cada autoridade gera sua chave privada secreta
        x_i = auth.gerar_chave_privada()
        print(f"Autoridade {auth.id}: x_i gerado (primeiros 20 dígitos): {str(x_i)[:20]}...")
        
        # Calcula sua chave pública parcial
        h_i = auth.calcular_chave_publica_parcial()
        print(f"Autoridade {auth.id}: h_i = g^x_i mod p calculado (primeiros 20 dígitos): {str(h_i)[:20]}...")
        
        # Submete ao servidor
        submissao = auth.submeter_chave_publica()
        submissoes.append(submissao)
    
    print("\n=== TASK 2.1 CONCLUÍDA ===\n")
```

---

## 🎯 Task 2.2: Rotina do Servidor (cálculo da chave pública conjunta $h$)

### O que a especificação pede?

> *"Implementar rotina do Servidor para receber $h_1, h_2, \dots, h_n$ e calcular a chave pública conjunta $h = \prod h_i \bmod p$."*

### Traduzindo os termos técnicos:

* **Servidor de Votação:** O componente central que gerencia a eleição. Não possui capacidade de decifrar cédulas sozinho (não conhece nenhuma $x_i$ individual).
* **Chave pública conjunta $h$:** É o produto de todas as chaves públicas parciais, módulo $p$:
  
  $$h = h_1 \times h_2 \times \dots \times h_n \pmod p$$

  Matematicamente, isso é equivalente a $h = g^{(x_1 + x_2 + \dots + x_n)} \bmod p = g^{x_{total}} \bmod p$, onde $x_{total}$ é a soma de todas as chaves privadas. Mas **ninguém conhece $x_{total}$** individualmente — cada autoridade sabe apenas seu próprio $x_i$.

* **Uso de $h$:** A chave pública conjunta $h$ será usada pelos eleitores na Fase 3 para cifrar seus votos via ElGamal Exponencial: $c_2 = g^m \cdot h^r \bmod p$.

### Implementação sugerida:

```python
# =====================================================================
# TASK 2.2: Rotina do Servidor de Votação
# =====================================================================

from cripto_base import P

class ServidorVotacao:
    """
    Gerencia o setup da eleição: coleta chaves públicas parciais
    das autoridades e compõe a chave pública conjunta.
    """
    
    def __init__(self):
        self.chaves_publicas_parciais = []  # Lista de dicts {'autoridade_id': id, 'h_i': valor}
        self.h_conjunta = None  # Chave pública conjunta h = prod(h_i) mod p
        self.eleitores_cadastrados = {}  # id_eleitor -> {'chave_publica_rsa': pem, 'votou': False}
    
    def receber_chave_publica_parcial(self, submissao: dict):
        """
        Recebe a submissão de uma autoridade e armazena sua h_i.
        """
        self.chaves_publicas_parciais.append(submissao)
        print(f"Servidor: recebeu h_i da Autoridade {submissao['autoridade_id']}")
    
    def calcular_chave_publica_conjunta(self):
        """
        Calcula h = h_1 * h_2 * ... * h_n mod p.
        Retorna o valor de h.
        """
        if not self.chaves_publicas_parciais:
            raise ValueError("Nenhuma chave pública parcial recebida ainda!")
        
        h = 1
        for submissao in self.chaves_publicas_parciais:
            h_i = submissao['h_i']
            h = (h * h_i) % P
        
        self.h_conjunta = h
        return h
    
    def obter_chave_publica_conjunta(self):
        """
        Retorna a chave pública conjunta h para ser usada na cifragem de votos.
        """
        if self.h_conjunta is None:
            raise ValueError("Chave pública conjunta ainda não foi calculada!")
        return self.h_conjunta
```

### Exemplo de uso e teste:

```python
if __name__ == "__main__":
    print("=== TESTE TASK 2.2: Servidor ===\n")
    
    # Simulando submissões de 3 autoridades (viriam da Task 2.1)
    from cripto_base import G, exp_mod
    
    # Simulando h_i recebidos (em produção viriam das autoridades reais)
    h_parciais_simuladas = [
        {'autoridade_id': 1, 'h_i': exp_mod(G, 12345, P)},
        {'autoridade_id': 2, 'h_i': exp_mod(G, 67890, P)},
        {'autoridade_id': 3, 'h_i': exp_mod(G, 54321, P)},
    ]
    
    servidor = ServidorVotacao()
    
    for submissao in h_parciais_simuladas:
        servidor.receber_chave_publica_parcial(submissao)
    
    h = servidor.calcular_chave_publica_conjunta()
    print(f"\nServidor: chave pública conjunta h calculada (primeiros 20 dígitos): {str(h)[:20]}...")
    
    print("\n=== TASK 2.2 CONCLUÍDA ===\n")
```

---

## 🎯 Task 2.3: Cadastro inicial de eleitores e geração de chaves RSA

### O que a especificação pede?

> *"Criar rotina de geração de pares de chaves RSA para um conjunto predefinido de eleitores (cadastro inicial e lista de elegibilidade)."*

### Traduzindo os termos técnicos:

* **Cadastro inicial:** Antes da eleição começar, existe uma lista pré-definida de eleitores elegíveis (por exemplo, funcionários de uma empresa, membros de uma associação, alunos de uma turma). Cada eleitor tem um ID único.
* **Lista de elegibilidade:** O Servidor mantém um registro de quais IDs estão autorizados a votar. Um eleitor não cadastrado não pode votar (verificado na Task 3.3 da Fase 3).
* **Par de chaves RSA por eleitor:** Cada eleitor elegível recebe seu próprio par de chaves RSA (2048 bits):
  - **Chave privada RSA:** Fica com o eleitor. Usada para assinar digitalmente sua cédula de voto (Fase 3).
  - **Chave pública RSA:** Fica registrada no Servidor. Usada para verificar a assinatura do eleitor e garantir integridade e não-repúdio.
* **Controle de unicidade:** O campo `votou: False` garante que cada eleitor vote apenas uma vez (verificado na Fase 3).

### Implementação sugerida:

```python
# =====================================================================
# TASK 2.3: Cadastro de Eleitores e Chaves RSA
# =====================================================================

from cripto_base import gerar_par_chaves_rsa

class CadastroEleitores:
    """
    Gerencia o cadastro inicial de eleitores elegíveis,
    gerando pares de chaves RSA para cada um.
    """
    
    def __init__(self):
        # id_eleitor -> {'chave_privada_rsa': pem, 'chave_publica_rsa': pem, 'votou': bool}
        self.eleitores = {}
    
    def cadastrar_eleitor(self, id_eleitor: str):
        """
        Cadastra um novo eleitor, gerando seu par de chaves RSA.
        Retorna as chaves (privada e pública) para entrega ao eleitor.
        """
        if id_eleitor in self.eleitores:
            raise ValueError(f"Eleitor {id_eleitor} já está cadastrado!")
        
        chave_privada_rsa, chave_publica_rsa = gerar_par_chaves_rsa()
        
        self.eleitores[id_eleitor] = {
            'chave_privada_rsa': chave_privada_rsa,
            'chave_publica_rsa': chave_publica_rsa,
            'votou': False
        }
        
        return {
            'id_eleitor': id_eleitor,
            'chave_privada_rsa': chave_privada_rsa,
            'chave_publica_rsa': chave_publica_rsa
        }
    
    def cadastrar_lote_eleitores(self, lista_ids: list):
        """
        Cadastra múltiplos eleitores de uma vez (cadastro inicial em lote).
        Retorna lista de dicts com as chaves de cada eleitor.
        """
        resultados = []
        for id_eleitor in lista_ids:
            resultado = self.cadastrar_eleitor(id_eleitor)
            resultados.append(resultado)
        return resultados
    
    def is_eleitor_elegivel(self, id_eleitor: str) -> bool:
        """Verifica se o eleitor está na lista de elegibilidade."""
        return id_eleitor in self.eleitores
    
    def ja_votou(self, id_eleitor: str) -> bool:
        """Verifica se o eleitor já votou (controle de unicidade)."""
        if id_eleitor not in self.eleitores:
            return True  # Eleitor não cadastrado não pode votar
        return self.eleitores[id_eleitor]['votou']
    
    def obter_chave_publica_rsa(self, id_eleitor: str) -> str:
        """Retorna a chave pública RSA de um eleitor para verificação de assinatura."""
        if id_eleitor not in self.eleitores:
            raise ValueError(f"Eleitor {id_eleitor} não cadastrado!")
        return self.eleitores[id_eleitor]['chave_publica_rsa']
    
    def obter_chave_privada_rsa(self, id_eleitor: str) -> str:
        """Retorna a chave privada RSA de um eleitor (apenas para uso do próprio eleitor)."""
        if id_eleitor not in self.eleitores:
            raise ValueError(f"Eleitor {id_eleitor} não cadastrado!")
        return self.eleitores[id_eleitor]['chave_privada_rsa']
    
    def marcar_como_votou(self, id_eleitor: str):
        """Marca o eleitor como tendo já votou (chamado pelo servidor na Fase 3)."""
        if id_eleitor not in self.eleitores:
            raise ValueError(f"Eleitor {id_eleitor} não cadastrado!")
        self.eleitores[id_eleitor]['votou'] = True
    
    def total_eleitores_cadastrados(self) -> int:
        return len(self.eleitores)
    
    def total_eleitores_que_votaram(self) -> int:
        return sum(1 for e in self.eleitores.values() if e['votou'])
```

### Exemplo de uso e teste:

```python
if __name__ == "__main__":
    print("=== TESTE TASK 2.3: Cadastro de Eleitores ===\n")
    
    cadastro = CadastroEleitores()
    
    # Cadastro inicial de um lote de eleitores predefinidos
    ids_eleitores = ["ELEITOR_001", "ELEITOR_002", "ELEITOR_003", "ELEITOR_004", "ELEITOR_005"]
    
    print(f"Cadastrando {len(ids_eleitores)} eleitores...\n")
    
    chaves_geradas = cadastro.cadastrar_lote_eleitores(ids_eleitores)
    
    for chave in chaves_geradas:
        print(f"Eleitor {chave['id_eleitor']}: par de chaves RSA gerado.")
        print(f"  Chave pública (primeiros 40 chars): {chave['chave_publica_rsa'][:40]}...")
    
    print(f"\nTotal de eleitores cadastrados: {cadastro.total_eleitores_cadastrados()}")
    print(f"Eleitor ELEITOR_001 é elegível? {cadastro.is_eleitor_elegivel('ELEITOR_001')}")
    print(f"Eleitor ELEITOR_999 é elegível? {cadastro.is_eleitor_elegivel('ELEITOR_999')}")
    
    print("\n=== TASK 2.3 CONCLUÍDA ===\n")
```

---

## 🔗 Integração das Tasks da Fase 2

Abaixo está um fluxo completo que integra as três tasks da Fase 2:

```python
# =====================================================================
# FLUXO COMPLETO DA FASE 2 - Setup da Eleição
# =====================================================================

from cripto_base import P, G, exp_mod

def executar_setup_fase2():
    print("=== INICIANDO SETUP DA FASE 2 ===\n")
    
    # --- ETAPA A: Autoridades geram e submetem chaves públicas parciais ---
    print("[Etapa A] Autoridades gerando chaves...")
    NUM_AUTORIDADES = 3
    autoridades = [AutoridadeEleitoral(id_autoridade=i+1) for i in range(NUM_AUTORIDADES)]
    
    submissoes_autoridades = []
    for auth in autoridades:
        auth.gerar_chave_privada()
        auth.calcular_chave_publica_parcial()
        submissoes_autoridades.append(auth.submeter_chave_publica())
    
    print(f"  -> {NUM_AUTORIDADES} autoridades submeteram suas h_i\n")
    
    # --- ETAPA B: Servidor calcula chave pública conjunta ---
    print("[Etapa B] Servidor calculando chave pública conjunta...")
    servidor = ServidorVotacao()
    
    for submissao in submissoes_autoridades:
        servidor.receber_chave_publica_parcial(submissao)
    
    h_conjunta = servidor.calcular_chave_publica_conjunta()
    print(f"  -> Chave pública conjunta h calculada\n")
    
    # --- ETAPA C: Cadastro inicial de eleitores ---
    print("[Etapa C] Cadastro inicial de eleitores...")
    cadastro = CadastroEleitores()
    
    ids_eleitores = ["ELEITOR_001", "ELEITOR_002", "ELEITOR_003",
                     "ELEITOR_004", "ELEITOR_005", "ELEITOR_006"]
    
    chaves_eleitores = cadastro.cadastrar_lote_eleitores(ids_eleitores)
    print(f"  -> {len(chaves_eleitores)} eleitores cadastrados com chaves RSA\n")
    
    print("=== SETUP DA FASE 2 CONCLUÍDO COM SUCESSO! ===\n")
    
    return servidor, cadastro, h_conjunta


if __name__ == "__main__":
    servidor, cadastro, h = executar_setup_fase2()
    
    print(f"Resumo do setup:")
    print(f"  - Chave pública conjunta h: {str(h)[:30]}...")
    print(f"  - Total de eleitores elegíveis: {cadastro.total_eleitores_cadastrados()}")
    print(f"  - Eleitores que já votaram: {cadastro.total_eleitores_que_votaram()}")
```

---

## 🧪 Como validar a Fase 2

Execute o script de teste acima e verifique:

1. **Task 2.1:** Cada autoridade gera um $x_i$ diferente e calcula $h_i = g^{x_i} \bmod p$ corretamente.
2. **Task 2.2:** O servidor consegue calcular $h = h_1 \times h_2 \times h_3 \bmod p$. Verifique que $h \neq h_i$ para qualquer $i$ individual.
3. **Task 2.3:** Cada eleitor cadastrado recebe um par único de chaves RSA. A lista de elegibilidade contém todos os IDs cadastrados.

### Teste de consistência matemática:

```python
# Verificando que h = g^(x_1 + x_2 + ... + x_n) mod p
x_total = sum(auth.x_i for auth in autoridades)
h_esperado = exp_mod(G, x_total, P)
h_calculado = servidor.obter_chave_publica_conjunta()

assert h_esperado == h_calculado, "Erro: h calculado não confere!"
print("✓ Consistência matemática verificada: h = g^(soma dos x_i) mod p")
```

---

## 💡 Resumo para a Apresentação ao Professor (Arguição)

Na especificação do trabalho, o professor fará perguntas individuais sobre a Fase 2. Aqui estão as respostas para as mais prováveis:

**1. "Por que cada autoridade tem sua própria $x_i$ secreta, em vez de uma chave privada única para todo o sistema?"**
- **Resposta:** Para evitar que uma única entidade tenha poder total sobre a eleição. Com $N \ge 3$ autoridades, nenhuma consegue decifrar votos sozinha. Apenas na fase de apuração (Fase 4), quando todas colaboram, a máscara completa é removida. Isso garante descentralização de confiança.

**2. "Como a chave pública conjunta $h = \prod h_i \bmod p$ é equivalente a $g^{x_{total}} \bmod p$?"**
- **Resposta:** Como $h_i = g^{x_i} \bmod p$, então $\prod h_i = \prod g^{x_i} = g^{(x_1 + x_2 + \dots + x_n)} \pmod p$. Portanto $h = g^{x_{total}} \bmod p$ onde $x_{total}$ é a soma secreta de todas as $x_i$. Ninguém conhece $x_{total}$ individualmente, mas todos podem usar $h$ para cifrar votos.

**3. "Por que precisamos cadastrar os eleitores antes da eleição, com chaves RSA individuais?"**
- **Resposta:** O cadastro inicial estabelece a lista de elegibilidade (quem pode votar) e permite o controle de unicidade (cada eleitor vota no máximo uma vez). As chaves RSA individuais permitem que cada eleitor assine digitalmente sua cédula, garantindo integridade e não-repúdio — o servidor pode verificar que o voto veio de um eleitor legítimo e não foi adulterado.

**4. "O que acontece se uma autoridade se recusar a submeter sua $h_i$?"**
- **Resposta:** A chave pública conjunta $h$ não pode ser calculada corretamente, e a eleição não pode prosseguir. Isso é uma proteção: o sistema requer a participação de todas as autoridades no setup.

---

## 📋 Checklist de Conclusão da Fase 2

- [ ] Task 2.1: Classe `AutoridadeEleitoral` implementada com geração de $x_i$ e cálculo de $h_i$
- [ ] Task 2.2: Classe `ServidorVotacao` implementada com recebimento de $h_i$ e cálculo de $h$
- [ ] Task 2.3: Classe `CadastroEleitores` implementada com geração de chaves RSA e lista de elegibilidade
- [ ] Fluxo integrado testado: autoridades → servidor → cadastro de eleitores
- [ ] Consistência matemática verificada: $h = g^{(\sum x_i)} \bmod p$
- [ ] Todos os testes individuais passando

---

## ➡️ Próximos passos (Fase 3)

Com a Fase 2 concluída, o sistema está pronto para:

1. **Task 3.1:** Modelar o Quadro Público (Bulletin Board) em JSON.
2. **Task 3.2:** Eleitor cria vetor de votos, cifra cédulas com ElGamal usando $h$, e assina com RSA.
3. **Task 3.3:** Servidor valida elegibilidade, unicidade e assinatura RSA.
4. **Task 3.4:** Servidor calcula hash SHA-256, grava no Quadro Público e retorna recibo assinado.

A chave pública conjunta $h$ calculada nesta fase será usada pelos eleitores na Task 3.2 para cifrar seus votos!