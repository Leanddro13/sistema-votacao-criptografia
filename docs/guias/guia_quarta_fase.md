# Aula 04: Apuração e Decifração Distribuída (Fase 4)

Parabéns por assumir a **Fase 4**! Esta é a etapa mais elegante e gratificante de todo o projeto. 

Recapitulando a nossa trajetória:
- **Fase 1:** Fabricamos os **tijolos e cadeados** (aritmética modular, ElGamal Exponencial, RSA, SHA-256).
- **Fase 2:** Erguemos as **paredes** (autoridades gerando chaves públicas parciais, chave conjunta $h$ e cadastro de eleitores).
- **Fase 3:** Abrimos as **portas** (eleitores votaram, as cédulas foram encadeadas no Quadro Público e recibos foram emitidos).

Agora, na **Fase 4**, a urna está lacrada e chegou o momento da **Apuração**. 

O nosso desafio: **Como contar os votos de cada candidato sem abrir a cédula de nenhum eleitor individualmente, e sem que nenhuma autoridade ou administrador tenha a chave mestra?**

---

## 🛠️ Antes de Começar: O Que Vamos Construir

Nesta fase, criaremos o arquivo **`src/apuracao.py`**. Ele vai consumir os dados do Quadro Público (Fase 3) e interagir com as Autoridades Eleitorais (Fase 2) usando a matemática que preparamos na Fase 1:

* De `src/cripto_base.py`: `P`, `G`, `exp_mod`, `inverso_mod`, `somar_cifras_homomorficamente`, `remover_mascara_elgamal`, `decifrar_logaritmo_discreto`.
* De `src/setup_eleicao.py`: Classe `AutoridadeEleitoral`.
* De `src/votacao.py`: Classe `QuadroPublico`.

Não é necessário instalar nenhuma nova dependência externa!

---

## 📚 Conceito Base: O "Ritual das Chaves" e a Mágica Homomórfica

### 1. Multiplicação das Cédulas (A Homomorfia em Ação)
Lembre-se de que no Quadro Público, para cada eleitor $j$, temos uma cédula com uma cifra $(c_{1,j}, c_{2,j})$ para cada candidato.

Para um candidato específico, o Servidor pega todas as cifras e as multiplica:
$$C_1 = \prod_{j=1}^{n} c_{1,j} \pmod p = g^{\sum r_j} \pmod p = g^{R_{total}} \pmod p$$
$$C_2 = \prod_{j=1}^{n} c_{2,j} \pmod p = g^{\sum m_j} \cdot h^{\sum r_j} \pmod p = g^{M} \cdot h^{R_{total}} \pmod p$$

Onde:
* $M$ é o **total de votos** recebidos por aquele candidato!
* $R_{total} = \sum r_j$ é a soma de todos os números aleatórios que os eleitores usaram.
* $h^{R_{total}}$ é a **máscara protetora** que impede o servidor de enxergar $g^M$.

### 2. Como as Autoridades Removem a Máscara Sem Revelar Seus Segredos?
Lembre-se da Fase 2: a chave pública conjunta é $h = g^{(x_1 + x_2 + \dots + x_N)} \pmod p$.
Logo, a máscara protetora é:
$$h^{R_{total}} = \left(g^{R_{total}}\right)^{(x_1 + x_2 + \dots + x_N)} = C_1^{(x_1 + x_2 + \dots + x_N)} \pmod p$$

Como nenhuma autoridade conhece a soma dos segredos alheios, o Servidor envia apenas o valor público $C_1$ para cada Autoridade $i$.
Cada autoridade calcula sua **decifração parcial**:
$$d_i = C_1^{x_i} \pmod p$$

Ao receber todos os $d_i$, o Servidor os multiplica:
$$S = d_1 \times d_2 \times \dots \times d_N \pmod p = C_1^{x_1} \times C_1^{x_2} \times \dots \times C_1^{x_N} = C_1^{(x_1 + \dots + x_N)} \pmod p$$

**Resultado incrível:** $S$ é exatamente igual à máscara $h^{R_{total}}$!

### 3. Extração Final do Resultado
Com a máscara $S$ em mãos, o Servidor faz:
1. Remove a máscara multiplicando pelo inverso modular:
   $$\text{isolado} = C_2 \times S^{-1} \pmod p = g^M \pmod p$$
2. Executa a busca exaustiva (Task 1.4): testa $g^0, g^1, g^2 \dots$ até achar qual bate com o valor isolado. **Esse número é a quantidade exata de votos do candidato!**

---

## 🎯 Task 4.1: Multiplicação Homomórfica no Servidor

### O que a especificação pede?
> *"Implementar rotina do Servidor para multiplicar os componentes $c_1$ e $c_2$ de todos os votos (por candidato) gerando $C_1$ e $C_2$."*

### O que fazer:
O Servidor lê todos os blocos do Quadro Público, separa as cifras de cada coluna (candidato) e calcula os produtos acumulados de $c_1$ e $c_2$.

```python
def agregar_cifras_por_candidato(quadro, candidatos: list, p: int) -> dict:
    """
    Para cada candidato, multiplica todos os c1 entre si e todos os c2 entre si.
    Retorna um dicionário:
    {
        'Alice': {'C1': valor, 'C2': valor, 'total_cedulas': n},
        'Bob':   {'C1': valor, 'C2': valor, 'total_cedulas': n},
        ...
    }
    """
    total_blocos = len(quadro.blocos)
    if total_blocos == 0:
        raise ValueError("O Quadro Público está vazio! Nenhum voto a ser apurado.")

    totais_por_candidato = {}

    for indice_candidato, nome_candidato in enumerate(candidatos):
        cifras_candidato = [
            (bloco['cedula'][indice_candidato]['c1'], bloco['cedula'][indice_candidato]['c2'])
            for bloco in quadro.blocos
        ]

        # Multiplicação homomórfica usando a função da Fase 1
        C1, C2 = somar_cifras_homomorficamente(cifras_candidato, p)
        totais_por_candidato[nome_candidato] = {
            'C1': C1,
            'C2': C2,
            'total_cedulas': total_blocos
        }

    return totais_por_candidato
```

---

## 🎯 Task 4.2: Rotina de Decifração Parcial das Autoridades

### O que a especificação pede?
> *"Implementar lógica das Autoridades para receber $C_1$ e calcular a decifração parcial $d_i = C_1^{x_i} \bmod p$."*

### O que fazer:
Atualizar a classe `AutoridadeEleitoral` (ou estendê-la) para incluir o método de cálculo de decifração parcial para cada candidato:

```python
def calcular_decifracao_parcial(self, C1: int, p: int) -> int:
    """
    Recebe o componente C1 agregado de um candidato e calcula a
    decifração parcial d_i = C1^(x_i) mod p usando seu segredo x_i.
    """
    if self.x_i is None:
        raise ValueError(f"Autoridade {self.id} não possui chave privada x_i!")
    
    # d_i = C1^(x_i) mod p
    d_i = exp_mod(C1, self.x_i, p)
    return d_i
```

Cada autoridade deve assinar ou identificar sua contribuição:
$$\text{pacote\_decifracao} = \{\text{'autoridade\_id'}: i,\; \text{'d\_i'}: d_i\}$$

---

## 🎯 Task 4.3: Combinação da Máscara e Apuração dos Vencedores

### O que a especificação pede?
> *"Implementar lógica do Servidor de receber os $d_i$, recuperar a máscara, extrair $g^M$ a partir de $C_2$ e usar a busca exaustiva (Task 1.4) para obter o resultado $M$."*

### O que fazer:
O Servidor junta todos os $d_i$ de cada candidato, calcula o produto $S = \prod d_i \pmod p$, cancela a máscara e faz a busca discreta.

```python
def apurar_resultado_candidato(C1: int, C2: int, lista_d_i: list, total_eleitores: int, p: int, g: int) -> int:
    """
    Combina as decifrações parciais d_i, remove a máscara de C2 e extrai M.
    """
    # 1. Combina as partes para reconstruir a máscara S = prod(d_i) mod p
    S = 1
    for d_i in lista_d_i:
        S = (S * d_i) % p

    # 2. Isola g^M multiplicando C2 pelo inverso modular de S
    g_elevado_M = remover_mascara_elgamal(C2, S, p)

    # 3. Busca exaustiva para achar M tal que g^M mod p == g_elevado_M
    # O total máximo de votos em um candidato é o total de cédulas no quadro
    total_votos = decifrar_logaritmo_discreto(g_elevado_M, max_votos_possiveis=total_eleitores, p=p, g=g)

    return total_votos
```

---

## 💻 Código Completo do Módulo `src/apuracao.py`

Aqui está a implementação completa e integrada que você vai criar em `src/apuracao.py`:

```python
import sys
from pathlib import Path

# Garante a resolução de imports
_SRC_DIR = Path(__file__).resolve().parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from cripto_base import (
    P, G, somar_cifras_homomorficamente, remover_mascara_elgamal,
    decifrar_logaritmo_discreto, exp_mod
)
from setup_eleicao import AutoridadeEleitoral
from votacao import QuadroPublico


class ApuradorEleicao:
    """
    Coordena a apuração homomórfica dos votos registrados no Quadro Público
    e a cooperação das autoridades eleitorais para decifração do resultado.
    """

    def __init__(self, quadro: QuadroPublico, autoridades: list):
        self.quadro = quadro
        self.autoridades = autoridades
        self.candidatos = quadro.configuracao['candidatos']
        self.P = quadro.configuracao.get('p', P)
        self.G = quadro.configuracao.get('g', G)

    def executar_apuracao(self) -> dict:
        """
        Executa o fluxo completo da apuração:
        1. Multiplica homomorficamente as cifras de cada candidato (Task 4.1).
        2. Coleta a decifração parcial de cada autoridade (Task 4.2).
        3. Reconstrói a máscara e recupera a soma dos votos (Task 4.3).
        """
        total_cedulas = len(self.quadro.blocos)
        if total_cedulas == 0:
            raise ValueError("Não há votos registrados no Quadro Público para apurar.")

        print(f"\n" + "="*50)
        print(f"INICIANDO APURAÇÃO HOMOMÓRFICA ({total_cedulas} votos registrados)")
        print("="*50)

        # Task 4.1: Agregação Homomórfica
        agregados = {}
        for i, nome in enumerate(self.candidatos):
            cifras = [(b['cedula'][i]['c1'], b['cedula'][i]['c2']) for b in self.quadro.blocos]
            C1, C2 = somar_cifras_homomorficamente(cifras, self.P)
            agregados[nome] = {'C1': C1, 'C2': C2}
            print(f" -> Candidato '{nome}': C1 e C2 homomórficos calculados.")

        # Task 4.2: Decifrações Parciais pelas Autoridades
        print(f"\n[Fase de Cooperação das {len(self.autoridades)} Autoridades]")
        decifracoes_parciais = {nome: [] for nome in self.candidatos}

        for auth in self.autoridades:
            for nome in self.candidatos:
                C1 = agregados[nome]['C1']
                d_i = exp_mod(C1, auth.x_i, self.P)
                decifracoes_parciais[nome].append({
                    'autoridade_id': auth.id,
                    'd_i': d_i
                })
            print(f" -> Autoridade {auth.id} forneceu decifrações parciais com sucesso.")

        # Task 4.3: Recombinação da Máscara e Extração de Votos
        print(f"\n[Reconstrução das Máscaras e Extração do Resultado]")
        resultado_final = {}

        for nome in self.candidatos:
            C1 = agregados[nome]['C1']
            C2 = agregados[nome]['C2']
            lista_d_i = [item['d_i'] for item in decifracoes_parciais[nome]]

            # S = prod(d_i) mod p
            S = 1
            for d in lista_d_i:
                S = (S * d) % self.P

            # Isola g^M = C2 * S^(-1) mod p
            g_M = remover_mascara_elgamal(C2, S, self.P)

            # Busca exaustiva do logaritmo discreto
            votos = decifrar_logaritmo_discreto(
                g_elevado_M=g_M,
                max_votos_possiveis=total_cedulas,
                p=self.P,
                g=self.G
            )
            resultado_final[nome] = votos
            print(f" 🏆 {nome}: {votos} voto(s)")

        print("="*50)
        print("APURAÇÃO CONCLUÍDA COM SUCESSO!")
        print("="*50 + "\n")

        return resultado_final
```

---

## 🧪 Testes e Validação Obrigatória (O Que Mostrar na Apresentação)

O professor exige expressamente na especificação:
> *"A demonstração ao vivo deverá incluir: (...) **A tentativa de apuração sem a participação de todas as autoridades e a sua falha.**"*

Para cobrir essa exigência com louvor, adicione no final do arquivo `src/apuracao.py` o teste de apuração completa e a simulação de falha:

```python
if __name__ == "__main__":
    from setup_eleicao import executar_setup_fase2
    from votacao import ServidorEleicao, Eleitor

    print("=== CONFIGURANDO ELEIÇÃO DE TESTE PARA A FASE 4 ===")
    CANDIDATOS = ["Alice", "Bob", "Carol"]
    
    # 1. Setup com 3 autoridades
    autoridades, servidor_setup, cadastro, h = executar_setup_fase2()
    servidor = ServidorEleicao(servidor_setup, CANDIDATOS)

    # 2. Votação de 5 eleitores
    # Esperado: Alice = 3 votos, Bob = 1 voto, Carol = 1 voto
    votos_simulados = {
        "ELEITOR_001": "Alice",
        "ELEITOR_002": "Bob",
        "ELEITOR_003": "Alice",
        "ELEITOR_004": "Carol",
        "ELEITOR_005": "Alice",
    }

    for id_eleitor, escolha in votos_simulados.items():
        eleitor = Eleitor(
            id_eleitor,
            cadastro.obter_chave_privada_rsa(id_eleitor),
            cadastro.obter_chave_publica_rsa(id_eleitor),
            h, CANDIDATOS
        )
        pacote = eleitor.votar(escolha)
        servidor.receber_voto(pacote)

    print(f"\nQuadro Público gerado com {len(servidor.quadro.blocos)} votos válidos.")

    # 3. Teste 1: Apuração normal com TODAS as autoridades (Deve funcionar)
    print("\n--- TESTE 1: Apuração Normal (Todas as autoridades participam) ---")
    apurador = ApuradorEleicao(servidor.quadro, autoridades)
    resultado = apurador.executar_apuracao()

    assert resultado == {"Alice": 3, "Bob": 1, "Carol": 1}
    print("✓ TESTE 1 PASSOU: Resultado apurado idêntico aos votos emitidos!\n")

    # 4. Teste 2: O ATAQUE / FALHA OBRIGATÓRIA DA APRESENTAÇÃO
    # Tentar apurar com apenas 2 das 3 autoridades (Autoridade 3 boicota ou está offline)
    print("--- TESTE 2: Tentativa de apuração sem a Autoridade 3 (Simulação de Falha) ---")
    autoridades_incompletas = autoridades[:2]  # apenas Autoridades 1 e 2
    apurador_incompleto = ApuradorEleicao(servidor.quadro, autoridades_incompletas)

    try:
        resultado_incompleto = apurador_incompleto.executar_apuracao()
        print("✗ ERRO GRAVE: A apuração funcionou sem todas as autoridades!")
    except ValueError as e:
        print(f"✓ TESTE 2 PASSOU: A apuração falhou conforme esperado matematicamente!")
        print(f"  Mensagem capturada: {e}")
```

---

## 💡 Resumo para a Arguição com o Professor (Perguntas da Fase 4)

Aqui estão as perguntas que o professor com certeza fará sobre a Fase 4:

### 1. "O que acontece matematicamente se uma autoridade faltar ou se recusar a participar da apuração?" *(Pergunta obrigatória do relatório!)*
* **Resposta Técnica:** 
  Se a autoridade $N$ não participar, o produto das decifrações parciais não atinge o segredo total:
  $$S_{incompleto} = C_1^{(x_1 + \dots + x_{N-1})} \neq C_1^{x_{total}}$$
  Ao tentar remover a máscara de $C_2$, o que sobra não é $g^M$, mas sim $g^M \cdot g^{R_{total} \cdot x_N} \pmod p$. Esse valor resultante é indistinguível de ruído aleatório. A busca exaustiva do logaritmo discreto testa até o limite máximo de eleitores e **falha com erro**, provando que é impossível decifrar o resultado sem 100% de cooperação das autoridades.

### 2. "O que acontece se todas as autoridades conspirarem entre si?" *(Pergunta obrigatória do relatório!)*
* **Resposta Técnica:**
  Se todas as autoridades se unirem maliciosamente, elas podem somar seus segredos privados:
  $$x_{total} = \sum x_i$$
  Com $x_{total}$, elas reconstroem a chave privada completa da eleição. Como o Quadro Público é público, elas conseguem aplicar a decifração ElGamal em cada cédula individual de cada bloco, **quebrando totalmente o sigilo dos votos**. Por isso, as autoridades devem ser escolhidas de entidades independentes com interesses conflitantes (ex: partidos rivais, OAB, Ministério Público).

### 3. "Por que a decifração parcial $d_i = C_1^{x_i} \bmod p$ não expõe o segredo $x_i$ da autoridade?"
* **Resposta Técnica:**
  Porque descobrir $x_i$ a partir de $C_1$ e $d_i$ recai no **Problema do Logaritmo Discreto** no grupo cíclico de 2048 bits. Como $x_i$ é um número aleatório gigantesco (2048 bits), nenhum computador atual consegue derivar $x_i$ a partir de $d_i$.

### 4. "Por que a ordem dos votos no Quadro Público não viola a justiça da eleição antes da hora?"
* **Resposta Técnica:**
  Porque antes da Fase 4, nenhuma autoridade calculou seus $d_i$. Mesmo que o administrador tente multiplicar os votos recebidos até as 14h, ele não tem como remover a máscara $h^R$ sem as autoridades. Logo, nenhum resultado parcial vaza antes do fechamento oficial da votação (**Garantia de Justiça / Fairness**).

---

## 📋 Checklist da Sua Entrega da Fase 4

- [ ] Criar o arquivo `src/apuracao.py`.
- [ ] Implementar a multiplicação homomórfica dos blocos (Task 4.1).
- [ ] Implementar o cálculo das decifrações parciais $d_i$ (Task 4.2).
- [ ] Implementar a remoção da máscara conjunta e extração de $M$ via logaritmo discreto (Task 4.3).
- [ ] Rodar os testes automatizados e verificar a rejeição da apuração incompleta.
- [ ] Documentar suas observações para o Relatório Técnico da Fase 6.
