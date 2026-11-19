# Aula 03: Sistema de Votação e Quadro Público (Fase 3)

Bem-vindo(a) de volta! Recapitulando a nossa obra:

- **Fase 1:** fabricamos os **tijolos e cadeados** (primitivas matemáticas).
- **Fase 2:** erguemos as **paredes** (autoridades, chave pública conjunta $h$ e cadastro de eleitores).

Agora, na **Fase 3**, o prédio finalmente **abre as portas**: os eleitores entram, votam e saem com um comprovante. Nesta fase vamos:

1. Criar o **Quadro Público** (*Bulletin Board*): um "livro-razão" público onde cada voto é uma página que não pode ser arrancada nem reescrita.
2. Programar o **Eleitor**: montar o vetor de votos, cifrar cada posição com ElGamal e assinar tudo com RSA.
3. Programar o **Servidor**: conferir se quem votou pode votar, se ainda não votou e se a assinatura é verdadeira.
4. Fazer o Servidor **gravar o voto no Quadro** (com hash encadeado) e devolver um **recibo assinado**.

Ainda **não** vamos apurar o resultado. Isso é a Fase 4.

---

## 🛠️ Antes de começar

Crie um novo arquivo **`votacao.py`** na raiz do projeto. Ele importa o que já fizemos:

- De `cripto_base.py` (Fase 1): `P`, `G`, `cifrar_voto_elgamal`, `gerar_par_chaves_rsa`, `assinar_dados_rsa`, `verificar_assinatura_rsa`, `calcular_hash_sha256`
- De `setup_eleicao.py` (Fase 2): `executar_setup_fase2()`, que devolve `(autoridades, servidor, cadastro, h)`

> ⚠️ **Dependência importante da Fase 2:** o Servidor da Fase 3 consulta `servidor.eleitores_cadastrados` para saber quem é elegível e qual é a chave pública RSA de cada eleitor. No nosso `setup_eleicao.py`, a função `executar_setup_fase2()` já preenche esse dicionário com **apenas as chaves públicas** (a privada fica com o eleitor). Se você seguiu o guia da Fase 2 ao pé da letra, confira se esse passo existe.

Não é preciso instalar nada novo: `json` e `datetime` já vêm com o Python.

---

## 📚 Conceito Base: Hash Encadeado (a corrente de lacres)

Imagine um caderno em que, no fim de cada página, você escreve a **impressão digital** (hash SHA-256) de tudo que está naquela página **mais** a impressão digital da página anterior:

```
 Configuração da eleição ──► hash_genesis
                                │
 Bloco 0: voto do João  + hash_genesis ──► hash_0
                                              │
 Bloco 1: voto da Maria + hash_0 ───────────► hash_1
                                              │
 Bloco 2: voto do Pedro + hash_1 ───────────► hash_2
```

Se alguém tentar alterar o voto do João no Bloco 0, o `hash_0` muda. Aí o Bloco 1 (que guardou o `hash_0` antigo) deixa de bater, e o Bloco 2 também, e assim por diante até o fim. **Uma única alteração quebra toda a corrente a partir dali**, e qualquer pessoa com o JSON consegue perceber.

### O detalhe que derruba muita gente: serialização canônica

Hash e assinatura RSA trabalham sobre **bytes**, não sobre "objetos". Os dicionários `{"a": 1, "b": 2}` e `{"b": 2, "a": 1}` são iguais para o Python, mas viram textos diferentes se você não tomar cuidado, e aí os hashes e as assinaturas **não batem**.

A solução é sempre transformar o dicionário em texto do **mesmo jeito**:

```python
json.dumps(dados, sort_keys=True, separators=(',', ':'))
```

- `sort_keys=True`: as chaves sempre saem em ordem alfabética.
- `separators=(',', ':')`: sem espaços extras.

Vamos chamar isso de `serializar_canonico()` e usar **em todo lugar** que precisar de hash ou assinatura.

---

## 🎯 Task 3.1: Estrutura do Quadro Público (JSON)

### O que a especificação pede?

> *"Modelar a estrutura do Quadro Público em formato serializável (ex: JSON)."*

### Traduzindo os termos técnicos:

* **Quadro Público (*Bulletin Board*):** uma lista pública onde só se **acrescenta** (*append-only*). Ninguém apaga nem edita. Qualquer pessoa (inclusive o Auditor da Fase 5) pode baixar e conferir.
* **Configuração:** os dados públicos da eleição que todos precisam conhecer: $p$, $g$, $h$, as $h_i$ das autoridades, a lista de candidatos e a chave pública RSA do servidor (para conferir os recibos).
* **Hash gênesis:** o "elo zero" da corrente. Usamos o hash da própria configuração. Assim, se alguém trocar o $h$ ou a lista de candidatos depois, a corrente inteira quebra.
* **Bloco:** um voto gravado. Contém:

| Campo | Para que serve |
|---|---|
| `indice` | Posição do bloco (0, 1, 2...) |
| `id_eleitor` | Quem votou (o **voto** é secreto, a **participação** é pública) |
| `chave_publica_eleitor` | Para o Auditor conferir a assinatura sem depender do servidor |
| `cedula` | Lista de cifras `{c1, c2}`, uma por candidato |
| `assinatura_eleitor` | Assinatura RSA do eleitor sobre `{id_eleitor, cedula}` |
| `timestamp` | Quando o voto foi gravado (UTC) |
| `hash_anterior` | O `hash_atual` do bloco anterior (ou o gênesis) |
| `hash_atual` | `SHA-256(hash_anterior + JSON canônico dos campos acima)` |

### Implementação sugerida:

```python
import json
from datetime import datetime, timezone

from cripto_base import (
    P, G, cifrar_voto_elgamal, gerar_par_chaves_rsa,
    assinar_dados_rsa, verificar_assinatura_rsa, calcular_hash_sha256,
)
from setup_eleicao import executar_setup_fase2

# =====================================================================
# TASK 3.1: Estrutura do Quadro Público (Bulletin Board)
# =====================================================================

def serializar_canonico(dados) -> str:
    """
    Converte um dict/lista em texto JSON SEMPRE igual para o mesmo conteúdo.
    sort_keys fixa a ordem das chaves e separators remove espaços,
    assim o hash e a assinatura dão o mesmo resultado em qualquer máquina.
    """
    return json.dumps(dados, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


class QuadroPublico:
    """
    Registro público append-only. Cada bloco aponta para o hash do anterior,
    formando uma corrente: alterar um bloco quebra todos os seguintes.
    """

    def __init__(self, configuracao: dict):
        # Dados públicos da eleição (p, g, h, candidatos, chave do servidor...)
        self.configuracao = configuracao
        # O "bloco zero" é o hash da própria configuração: a corrente fica
        # amarrada aos parâmetros da eleição.
        self.hash_genesis = calcular_hash_sha256(serializar_canonico(configuracao))
        self.blocos = []

    def ultimo_hash(self) -> str:
        if not self.blocos:
            return self.hash_genesis
        return self.blocos[-1]['hash_atual']

    def adicionar_bloco(self, dados_bloco: dict) -> dict:
        """
        Encadeia e grava um novo bloco.
        hash_atual = SHA-256(hash_anterior + JSON canônico dos dados do bloco)
        """
        hash_anterior = self.ultimo_hash()
        hash_atual = calcular_hash_sha256(hash_anterior + serializar_canonico(dados_bloco))

        bloco = dict(dados_bloco)
        bloco['hash_anterior'] = hash_anterior
        bloco['hash_atual'] = hash_atual

        self.blocos.append(bloco)
        return bloco

    def para_dict(self) -> dict:
        return {
            'configuracao': self.configuracao,
            'hash_genesis': self.hash_genesis,
            'blocos': self.blocos,
        }

    def salvar_json(self, caminho: str):
        with open(caminho, 'w', encoding='utf-8') as f:
            json.dump(self.para_dict(), f, indent=2, ensure_ascii=False)

    @classmethod
    def carregar_json(cls, caminho: str) -> 'QuadroPublico':
        with open(caminho, 'r', encoding='utf-8') as f:
            dados = json.load(f)
        quadro = cls(dados['configuracao'])
        quadro.blocos = dados['blocos']
        return quadro
```

> 💡 **E os números de 2048 bits no JSON?** O `json` do Python grava e lê inteiros de qualquer tamanho sem perder nada. Isso basta para o nosso Auditor (também em Python). Se um dia outro programa em outra linguagem precisar ler o quadro, o mais seguro é guardar `c1`/`c2` como texto hexadecimal.

---

## 🗳️ Task 3.2: Lógica do Eleitor

### O que a especificação pede?

> *"Implementar a lógica do Eleitor: criar o vetor de votos (1 para o escolhido, 0 para os demais), gerar $r$ aleatório para cada um, cifrar as cédulas e aplicar assinatura RSA no pacote."*

### Traduzindo os termos técnicos:

* **Vetor de votos:** com os candidatos `["Alice", "Bob", "Carol"]`, quem vota em Bob gera `[0, 1, 0]`. Cada posição é um "sim/não" para um candidato.
* **Por que cifrar cada posição separadamente?** Porque na Fase 4 vamos **somar** os votos de cada candidato multiplicando as cifras daquela posição. A soma homomórfica só funciona se cada cifra guardar um único número pequeno (0 ou 1).
* **$r$ aleatório para cada posição:** é o que faz duas cifras de "0" saírem **completamente diferentes**. Sem isso, quem olhasse o quadro veria quais posições são iguais e descobriria o voto. A nossa `cifrar_voto_elgamal()` da Fase 1 já sorteia um $r$ novo a cada chamada.
* **Assinatura RSA no pacote:** o eleitor assina `{id_eleitor, cedula}` com sua **chave privada**. Isso prova que o pacote veio dele (autenticidade) e que ninguém mexeu no caminho (integridade).
* **Recibo:** depois de votar, o eleitor recebe do servidor um comprovante assinado com o hash do seu bloco. Com ele, pode conferir no Quadro Público que seu voto está lá (**verificabilidade individual**).

### Implementação sugerida:

```python
# =====================================================================
# TASK 3.2: Lógica do Eleitor
# =====================================================================

class Eleitor:
    """
    Cliente do eleitor: monta o vetor de votos, cifra cada posição com
    ElGamal Exponencial e assina o pacote com sua chave privada RSA.
    """

    def __init__(self, id_eleitor: str, chave_privada_rsa: str, chave_publica_rsa: str,
                 h_conjunta: int, candidatos: list):
        self.id = id_eleitor
        self.chave_privada_rsa = chave_privada_rsa
        self.chave_publica_rsa = chave_publica_rsa
        self.h = h_conjunta
        self.candidatos = candidatos
        self.recibo = None

    def criar_vetor_votos(self, candidato_escolhido: str) -> list:
        """1 na posição do candidato escolhido, 0 nas demais."""
        if candidato_escolhido not in self.candidatos:
            raise ValueError(f"Candidato '{candidato_escolhido}' não existe!")
        return [1 if c == candidato_escolhido else 0 for c in self.candidatos]

    def cifrar_cedula(self, vetor_votos: list) -> list:
        """
        Cifra cada posição separadamente. cifrar_voto_elgamal sorteia um r
        novo a cada chamada, então duas cifras de '0' nunca saem iguais.
        """
        cedula = []
        for voto in vetor_votos:
            c1, c2 = cifrar_voto_elgamal(voto, self.h)
            cedula.append({'c1': c1, 'c2': c2})
        return cedula

    def votar(self, candidato_escolhido: str) -> dict:
        """Gera o pacote assinado que será enviado ao servidor."""
        vetor = self.criar_vetor_votos(candidato_escolhido)
        cedula = self.cifrar_cedula(vetor)

        conteudo = {'id_eleitor': self.id, 'cedula': cedula}
        assinatura = assinar_dados_rsa(self.chave_privada_rsa, serializar_canonico(conteudo))

        return {'id_eleitor': self.id, 'cedula': cedula, 'assinatura': assinatura}

    def verificar_recibo(self, recibo: dict, chave_publica_servidor: str) -> bool:
        """Confere se o recibo foi mesmo assinado pelo servidor e é deste eleitor."""
        dados = recibo['dados']
        if dados['id_eleitor'] != self.id:
            return False
        valido = verificar_assinatura_rsa(
            chave_publica_servidor, serializar_canonico(dados), recibo['assinatura_servidor']
        )
        if valido:
            self.recibo = recibo
        return valido
```

### Exemplo do pacote gerado:

```python
{
    'id_eleitor': 'ELEITOR_002',
    'cedula': [
        {'c1': 1873...4421, 'c2': 9930...1187},   # Alice -> cifra de 0
        {'c1': 5521...0093, 'c2': 3317...7764},   # Bob   -> cifra de 1
        {'c1': 7710...2208, 'c2': 4402...6610},   # Carol -> cifra de 0
    ],
    'assinatura': '5f3a9c...e81b'                 # RSA-PSS em hexadecimal
}
```

Repare que, olhando só para os números, é **impossível** dizer qual posição é o "1".

---

## 🛡️ Task 3.3: Validação no Servidor

### O que a especificação pede?

> *"Implementar a validação no Servidor: conferir elegibilidade (ID existe), unicidade (ID não votou), e verificar assinatura RSA."*

### Traduzindo os termos técnicos:

* **Elegibilidade:** o `id_eleitor` está na lista montada na Fase 2? Se não está, o voto é recusado.
* **Unicidade:** o eleitor já votou? Se sim, recusado. É isso que impede o "voto duplo".
* **Assinatura RSA:** o servidor recalcula o JSON canônico de `{id_eleitor, cedula}` e confere a assinatura com a **chave pública** do eleitor que está no cadastro. Se alguém trocou uma única cifra no caminho, ou assinou com outra chave, a verificação falha.
* **Checagem de formato (extra, mas importante):** antes de tudo, o servidor confere se a cédula tem **exatamente uma cifra por candidato** e se `c1` e `c2` estão no intervalo $[1, p-1]$. Uma cédula com cifras faltando ou valores absurdos atrapalharia a apuração da Fase 4.

O servidor também passa a ter seu **próprio par de chaves RSA**, usado na Task 3.4 para assinar os recibos. Ele monta a configuração pública e cria o Quadro.

### O que o servidor **não** consegue verificar

O servidor **não sabe** se a cifra contém 0 ou 1. Ele não tem a chave privada! Um eleitor mal-intencionado poderia cifrar um `5` em vez de `1` e dar 5 votos a um candidato. Impedir isso exige **provas de conhecimento zero** (*zero-knowledge proofs*), que estão fora do escopo deste trabalho. Esse é exatamente um dos pontos que o relatório da **Fase 6** deve discutir (fraude em votos $\neq 0/1$).

### Implementação sugerida:

```python
# =====================================================================
# TASKS 3.3 e 3.4: Servidor recebe, valida, grava e emite recibo
# =====================================================================

class ServidorEleicao:
    """
    Recebe as cédulas dos eleitores. Usa o servidor da Fase 2 (que tem h e
    a lista de eleitores com suas chaves públicas) e um Quadro Público.
    """

    def __init__(self, servidor_setup, candidatos: list):
        self.servidor_setup = servidor_setup
        self.candidatos = candidatos

        # Par RSA do próprio servidor, usado para assinar os recibos
        self.chave_privada_rsa, self.chave_publica_rsa = gerar_par_chaves_rsa()

        configuracao = {
            'p': P,
            'g': G,
            'h': servidor_setup.obter_chave_publica_conjunta(),
            'h_parciais': servidor_setup.chaves_publicas_parciais,
            'candidatos': candidatos,
            'chave_publica_servidor': self.chave_publica_rsa,
        }
        self.quadro = QuadroPublico(configuracao)

    # ---------------- TASK 3.3: validação ----------------

    def validar_pacote(self, pacote: dict):
        """
        Retorna (True, 'OK') ou (False, motivo). Ordem das checagens:
        formato -> elegibilidade -> unicidade -> assinatura.
        """
        eleitores = self.servidor_setup.eleitores_cadastrados

        # 0. Formato da cédula: uma cifra por candidato, valores no grupo
        cedula = pacote.get('cedula')
        if not isinstance(cedula, list) or len(cedula) != len(self.candidatos):
            return False, "Cédula malformada (número de cifras != número de candidatos)"
        for cifra in cedula:
            for chave in ('c1', 'c2'):
                valor = cifra.get(chave) if isinstance(cifra, dict) else None
                if not isinstance(valor, int) or not (1 <= valor < P):
                    return False, "Cédula malformada (cifra fora do intervalo [1, p-1])"

        id_eleitor = pacote.get('id_eleitor')

        # 1. Elegibilidade: o ID está na lista do cadastro?
        if id_eleitor not in eleitores:
            return False, f"Eleitor {id_eleitor} não é elegível"

        # 2. Unicidade: ele já votou?
        if eleitores[id_eleitor]['votou']:
            return False, f"Eleitor {id_eleitor} já votou"

        # 3. Assinatura RSA: o pacote veio mesmo dele e não foi alterado?
        conteudo = {'id_eleitor': id_eleitor, 'cedula': cedula}
        chave_publica = eleitores[id_eleitor]['chave_publica_rsa']
        if not verificar_assinatura_rsa(chave_publica, serializar_canonico(conteudo), pacote['assinatura']):
            return False, "Assinatura RSA inválida"

        return True, "OK"
```

> 💡 **Por que a assinatura é a última checagem?** Verificar RSA é a operação mais cara. Checar formato, elegibilidade e unicidade primeiro descarta lixo e repetições de forma barata.

---

## 🔗 Task 3.4: Gravação com Hash Encadeado e Recibo Assinado

### O que a especificação pede?

> *"Implementar rotina do Servidor de calcular o hash SHA-256 (hash anterior + nova cédula), gravar no Quadro Público e retornar o recibo assinado ao eleitor."*

### Traduzindo os termos técnicos:

* **Calcular o hash:** é o `adicionar_bloco()` da Task 3.1: `SHA-256(hash_anterior + JSON canônico do bloco)`.
* **Gravar no Quadro Público:** acrescentar o bloco no fim da lista e **só então** marcar o eleitor como `votou = True`. Se algo der errado antes de gravar, o eleitor não perde o direito de votar.
* **Recibo assinado:** um pequeno documento `{id_eleitor, indice, hash_bloco, timestamp}` assinado com a **chave privada do servidor**. Ele serve para duas coisas:
  1. O eleitor confere no Quadro Público que existe um bloco com aquele hash (**seu voto foi registrado**).
  2. Se o servidor "sumir" com o voto depois, o eleitor tem uma **prova assinada** de que o servidor o aceitou (o servidor não pode negar: não-repúdio).
* **O recibo revela o voto?** Não! Ele só tem o hash do bloco, e o bloco só tem cifras. Isso é essencial: se o recibo provasse **em quem** a pessoa votou, ela poderia vendê-lo (ou ser coagida). Discuta isso no relatório da Fase 6.

### Implementação sugerida (continuação da classe `ServidorEleicao`):

```python
    # ---------------- TASK 3.4: gravação e recibo ----------------

    def receber_voto(self, pacote: dict) -> dict:
        valido, motivo = self.validar_pacote(pacote)
        if not valido:
            raise ValueError(f"Voto rejeitado: {motivo}")

        id_eleitor = pacote['id_eleitor']
        dados_bloco = {
            'indice': len(self.quadro.blocos),
            'id_eleitor': id_eleitor,
            'chave_publica_eleitor': self.servidor_setup.eleitores_cadastrados[id_eleitor]['chave_publica_rsa'],
            'cedula': pacote['cedula'],
            'assinatura_eleitor': pacote['assinatura'],
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        bloco = self.quadro.adicionar_bloco(dados_bloco)

        # Só marca como votou DEPOIS de gravar com sucesso
        self.servidor_setup.eleitores_cadastrados[id_eleitor]['votou'] = True

        return self.emitir_recibo(bloco)

    def emitir_recibo(self, bloco: dict) -> dict:
        dados_recibo = {
            'id_eleitor': bloco['id_eleitor'],
            'indice': bloco['indice'],
            'hash_bloco': bloco['hash_atual'],
            'timestamp': bloco['timestamp'],
        }
        assinatura = assinar_dados_rsa(self.chave_privada_rsa, serializar_canonico(dados_recibo))
        return {'dados': dados_recibo, 'assinatura_servidor': assinatura}
```

---

## 🔁 Integração das Tasks da Fase 3

O fluxo completo: setup da Fase 2 → servidor abre a votação → eleitores votam e conferem seus recibos.

```python
# =====================================================================
# FLUXO COMPLETO DA FASE 3
# =====================================================================

if __name__ == "__main__":
    CANDIDATOS = ["Alice", "Bob", "Carol"]

    autoridades, servidor_setup, cadastro, h = executar_setup_fase2()
    servidor = ServidorEleicao(servidor_setup, CANDIDATOS)

    def criar_eleitor(id_eleitor):
        return Eleitor(id_eleitor,
                       cadastro.obter_chave_privada_rsa(id_eleitor),
                       cadastro.obter_chave_publica_rsa(id_eleitor),
                       h, CANDIDATOS)

    print("=== INICIANDO VOTAÇÃO (FASE 3) ===\n")
    escolhas = {"ELEITOR_001": "Alice", "ELEITOR_002": "Bob", "ELEITOR_003": "Alice",
                "ELEITOR_004": "Carol", "ELEITOR_005": "Alice"}

    for id_eleitor, candidato in escolhas.items():
        eleitor = criar_eleitor(id_eleitor)
        recibo = servidor.receber_voto(eleitor.votar(candidato))
        ok = eleitor.verificar_recibo(recibo, servidor.chave_publica_rsa)
        print(f" -> {id_eleitor} votou. Bloco #{recibo['dados']['indice']} "
              f"hash={recibo['dados']['hash_bloco'][:16]}... recibo válido? {ok}")

    servidor.quadro.salvar_json("quadro_publico.json")
    print("\nQuadro Público salvo em quadro_publico.json")
```

> ⚠️ O `quadro_publico.json` é gerado a cada execução. Considere adicioná-lo ao `.gitignore`.

---

## 🧪 Como validar a Fase 3

Além do fluxo feliz, **tente atacar o sistema**. Cada ataque abaixo deve ser **recusado**:

```python
    print("\n=== ATAQUES QUE DEVEM SER BLOQUEADOS ===\n")

    def tentar(descricao, pacote):
        try:
            servidor.receber_voto(pacote)
            print(f" ✗ {descricao}: ACEITO (erro!)")
            raise AssertionError(descricao)
        except ValueError as e:
            print(f" ✓ {descricao}: {e}")

    # 1. Voto duplo
    tentar("Votar duas vezes", criar_eleitor("ELEITOR_001").votar("Bob"))

    # 2. Eleitor fora da lista
    intruso = Eleitor("INTRUSO", *gerar_par_chaves_rsa(), h, CANDIDATOS)
    tentar("Eleitor não cadastrado", intruso.votar("Bob"))

    # 3. Alguém troca as cifras de lugar depois da assinatura
    pacote = criar_eleitor("ELEITOR_006").votar("Bob")
    pacote['cedula'][0], pacote['cedula'][1] = pacote['cedula'][1], pacote['cedula'][0]
    tentar("Cédula adulterada após assinatura", pacote)

    # 4. Alguém se passa pelo ELEITOR_006 com outra chave
    falso = Eleitor("ELEITOR_006", *gerar_par_chaves_rsa(), h, CANDIDATOS)
    tentar("Assinatura com chave errada", falso.votar("Bob"))

    # 5. Cédula incompleta
    pacote = criar_eleitor("ELEITOR_006").votar("Bob")
    pacote['cedula'] = pacote['cedula'][:2]
    tentar("Cédula com cifras faltando", pacote)
```

E confira a integridade do quadro:

```python
    # Cada bloco aponta para o hash do anterior e o próprio hash confere
    anterior = servidor.quadro.hash_genesis
    for bloco in servidor.quadro.blocos:
        dados = {k: v for k, v in bloco.items() if k not in ('hash_anterior', 'hash_atual')}
        assert bloco['hash_anterior'] == anterior
        assert bloco['hash_atual'] == calcular_hash_sha256(anterior + serializar_canonico(dados))
        anterior = bloco['hash_atual']
    print(f"✓ Cadeia de {len(servidor.quadro.blocos)} blocos íntegra")

    # Salvar e recarregar não perde nada (nem os inteiros de 2048 bits)
    recarregado = QuadroPublico.carregar_json("quadro_publico.json")
    assert recarregado.para_dict() == servidor.quadro.para_dict()
    print("✓ Quadro salvo e recarregado em JSON sem perdas")
```

### Teste de sanidade (spoiler da Fase 4):

Para ter certeza de que as cifras gravadas estão corretas, dá para apurar **usando a soma das $x_i$ diretamente**. Isso é **só para teste**: na eleição de verdade, ninguém conhece $x_{total}$, e na Fase 4 cada autoridade fará apenas a sua parte.

```python
    from cripto_base import (somar_cifras_homomorficamente, exp_mod,
                             remover_mascara_elgamal, decifrar_logaritmo_discreto)

    x_total = sum(a.x_i for a in autoridades)
    for i, nome in enumerate(CANDIDATOS):
        cifras = [(b['cedula'][i]['c1'], b['cedula'][i]['c2']) for b in servidor.quadro.blocos]
        C1, C2 = somar_cifras_homomorficamente(cifras)
        M = decifrar_logaritmo_discreto(remover_mascara_elgamal(C2, exp_mod(C1, x_total, P)), len(cifras))
        print(f"✓ {nome}: {M} voto(s)")
    # Esperado: Alice 3, Bob 1, Carol 1
```

---

## 💡 Resumo para a Apresentação ao Professor (Arguição)

**1. "Por que cada candidato tem uma cifra separada, em vez de cifrar o número do candidato escolhido?"**
- **Resposta:** Porque a soma homomórfica do ElGamal Exponencial soma os **expoentes**. Se cifrássemos "candidato 3", somar as cifras daria a soma dos números dos candidatos, o que não diz quantos votos cada um teve. Com um vetor de 0/1 por candidato, multiplicar as cifras de uma posição dá exatamente o total de votos daquele candidato, e a busca exaustiva da Fase 1 funciona porque o total é pequeno.

**2. "Duas cédulas iguais (ex.: dois votos em Bob) ficam iguais no quadro?"**
- **Resposta:** Não. Cada cifra usa um $r$ aleatório novo, então $c_1 = g^r$ e $c_2 = g^m h^r$ mudam a cada vez. Isso é a **cifragem probabilística**, e sem ela daria para agrupar votos iguais e até descobrir votos por comparação.

**3. "O que acontece se alguém alterar um voto já gravado no Quadro Público?"**
- **Resposta:** O `hash_atual` daquele bloco deixa de bater com seu conteúdo, e o `hash_anterior` do bloco seguinte deixa de bater também. Qualquer pessoa que recalcule a cadeia (o Auditor da Fase 5) detecta a fraude. Além disso, a assinatura RSA do eleitor deixa de ser válida para a cédula alterada.

**4. "Para que serve o recibo, e ele permite vender o voto?"**
- **Resposta:** O recibo prova que o servidor **aceitou e gravou** o voto (com o hash do bloco), permitindo ao eleitor conferir no quadro e cobrar o servidor se o bloco sumir. Ele **não** revela em quem a pessoa votou, porque só contém o hash de cifras. Por isso não serve como prova para venda de voto.

**5. "O servidor consegue saber em quem cada um votou?"**
- **Resposta:** Não. O servidor sabe **quem** votou (precisa saber, para impedir voto duplo), mas só vê cifras ElGamal. Para decifrar seria preciso $x_{total} = x_1 + \dots + x_n$, que só existe "espalhado" entre as autoridades.

**6. "O servidor consegue impedir um eleitor de cifrar um voto 5 em vez de 1?"**
- **Resposta:** Não nesta implementação. O servidor não tem como olhar dentro da cifra. A solução real são provas de conhecimento zero de que $m \in \{0, 1\}$ e de que o vetor soma 1. É uma limitação conhecida, a ser discutida no relatório (Fase 6).

---

## 📋 Checklist de Conclusão da Fase 3

- [x] `serializar_canonico()` implementada e usada em **todo** hash e assinatura
- [x] Task 3.1: Classe `QuadroPublico` com configuração, hash gênesis, `adicionar_bloco()` e salvar/carregar JSON
- [x] Task 3.2: Classe `Eleitor` com vetor de votos, cifragem por candidato, assinatura RSA e verificação de recibo
- [x] Task 3.3: `ServidorEleicao.validar_pacote()` checando formato, elegibilidade, unicidade e assinatura
- [x] Task 3.4: `ServidorEleicao.receber_voto()` gravando com hash encadeado e emitindo recibo assinado
- [x] Os 5 ataques da seção de validação são recusados
- [x] Cadeia de hashes íntegra e JSON recarregado sem perdas
- [x] Teste de sanidade apura o resultado esperado

---

## ➡️ Próximos passos (Fase 4)

Com os votos cifrados gravados no Quadro Público, a Fase 4 faz a apuração **sem que ninguém conheça a chave privada completa**:

1. **Task 4.1:** Servidor multiplica os $c_1$ e os $c_2$ de cada candidato, gerando $C_1$ e $C_2$.
2. **Task 4.2:** Cada Autoridade recebe $C_1$ e calcula sua decifração parcial $d_i = C_1^{x_i} \bmod p$.
3. **Task 4.3:** Servidor combina os $d_i$ na máscara $S = \prod d_i$, extrai $g^M = C_2 \cdot S^{-1}$ e usa a busca exaustiva (Task 1.4) para obter $M$.
