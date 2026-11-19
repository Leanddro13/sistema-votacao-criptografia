from cripto_base import P, G, exp_mod, gerar_numero_aleatorio_seguro, gerar_par_chaves_rsa

# =====================================================================
# TASK 2.1: Rotina das Autoridades Eleitorais
# =====================================================================

class AutoridadeEleitoral:
    """
    Representa uma Autoridade Eleitoral que detém um fragmento da chave privada.
    """

    def __init__(self, id_autoridade: int):
        self.id = id_autoridade
        self.x_i = None  # Chave privada secreta (nunca compartilhada)
        self.h_i = None  # Chave pública parcial (enviada ao servidor)

    def gerar_chave_privada(self):
        """Gera a chave privada secreta x_i no intervalo [1, p-1]."""
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
        """Retorna a chave pública parcial para submissão ao Servidor."""
        if self.h_i is None:
            raise ValueError("Chave pública parcial h_i ainda não foi calculada!")

        return {
            'autoridade_id': self.id,
            'h_i': self.h_i
        }


# =====================================================================
# TASK 2.2: Rotina do Servidor de Votação
# =====================================================================

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
        """Recebe a submissão de uma autoridade e armazena sua h_i."""
        ids_recebidos = {s['autoridade_id'] for s in self.chaves_publicas_parciais}
        if submissao['autoridade_id'] in ids_recebidos:
            raise ValueError(f"Autoridade {submissao['autoridade_id']} já submeteu sua h_i!")

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
            h = (h * submissao['h_i']) % P

        self.h_conjunta = h
        return h

    def obter_chave_publica_conjunta(self):
        """Retorna a chave pública conjunta h para ser usada na cifragem de votos."""
        if self.h_conjunta is None:
            raise ValueError("Chave pública conjunta ainda não foi calculada!")
        return self.h_conjunta


# =====================================================================
# TASK 2.3: Cadastro de Eleitores e Chaves RSA
# =====================================================================

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
        return [self.cadastrar_eleitor(id_eleitor) for id_eleitor in lista_ids]

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
        """Marca o eleitor como tendo já votado (chamado pelo servidor na Fase 3)."""
        if id_eleitor not in self.eleitores:
            raise ValueError(f"Eleitor {id_eleitor} não cadastrado!")
        self.eleitores[id_eleitor]['votou'] = True

    def total_eleitores_cadastrados(self) -> int:
        return len(self.eleitores)

    def total_eleitores_que_votaram(self) -> int:
        return sum(1 for e in self.eleitores.values() if e['votou'])


# =====================================================================
# FLUXO COMPLETO DA FASE 2 - Setup da Eleição
# =====================================================================

def executar_setup_fase2(num_autoridades: int = 3, ids_eleitores: list = None):
    if num_autoridades < 3:
        raise ValueError("A especificação exige N >= 3 autoridades!")

    if ids_eleitores is None:
        ids_eleitores = [f"ELEITOR_{i:03d}" for i in range(1, 7)]

    print("=== INICIANDO SETUP DA FASE 2 ===\n")

    # --- ETAPA A: Autoridades geram e submetem chaves públicas parciais ---
    print("[Etapa A] Autoridades gerando chaves...")
    autoridades = [AutoridadeEleitoral(id_autoridade=i + 1) for i in range(num_autoridades)]

    submissoes_autoridades = []
    for auth in autoridades:
        auth.gerar_chave_privada()
        auth.calcular_chave_publica_parcial()
        submissoes_autoridades.append(auth.submeter_chave_publica())

    print(f"  -> {num_autoridades} autoridades submeteram suas h_i\n")

    # --- ETAPA B: Servidor calcula chave pública conjunta ---
    print("[Etapa B] Servidor calculando chave pública conjunta...")
    servidor = ServidorVotacao()

    for submissao in submissoes_autoridades:
        servidor.receber_chave_publica_parcial(submissao)

    h_conjunta = servidor.calcular_chave_publica_conjunta()
    print("  -> Chave pública conjunta h calculada\n")

    # --- ETAPA C: Cadastro inicial de eleitores ---
    print("[Etapa C] Cadastro inicial de eleitores...")
    cadastro = CadastroEleitores()
    chaves_eleitores = cadastro.cadastrar_lote_eleitores(ids_eleitores)

    # O servidor guarda apenas as chaves PÚBLICAS (a privada fica com o eleitor)
    for chave in chaves_eleitores:
        servidor.eleitores_cadastrados[chave['id_eleitor']] = {
            'chave_publica_rsa': chave['chave_publica_rsa'],
            'votou': False
        }

    print(f"  -> {len(chaves_eleitores)} eleitores cadastrados com chaves RSA\n")

    print("=== SETUP DA FASE 2 CONCLUÍDO COM SUCESSO! ===\n")

    return autoridades, servidor, cadastro, h_conjunta


# =====================================================================
# TESTES DA FASE 2
# =====================================================================

if __name__ == "__main__":
    autoridades, servidor, cadastro, h = executar_setup_fase2()

    print("=== VALIDAÇÕES ===\n")

    # Task 2.1: cada autoridade tem x_i distinto e h_i = g^x_i mod p
    xs = [auth.x_i for auth in autoridades]
    assert len(set(xs)) == len(xs), "Erro: autoridades geraram x_i repetidos!"
    for auth in autoridades:
        assert auth.h_i == exp_mod(G, auth.x_i, P), f"Erro: h_i da Autoridade {auth.id} incorreto!"
    print("✓ Task 2.1: x_i distintos e h_i = g^x_i mod p para todas as autoridades")

    # Task 2.2: h = g^(soma dos x_i) mod p e h != h_i individual
    x_total = sum(xs)
    assert exp_mod(G, x_total, P) == servidor.obter_chave_publica_conjunta(), "Erro: h calculado não confere!"
    assert all(h != auth.h_i for auth in autoridades), "Erro: h coincide com algum h_i!"
    print("✓ Task 2.2: h = g^(soma dos x_i) mod p, e h difere de toda h_i")

    try:
        servidor.receber_chave_publica_parcial(autoridades[0].submeter_chave_publica())
        raise AssertionError("Erro: servidor aceitou submissão duplicada!")
    except ValueError:
        print("✓ Task 2.2: submissão duplicada de autoridade rejeitada")

    # Task 2.3: chaves RSA únicas, elegibilidade e unicidade
    pubs = [e['chave_publica_rsa'] for e in cadastro.eleitores.values()]
    assert len(set(pubs)) == len(pubs), "Erro: chaves RSA repetidas!"
    assert cadastro.is_eleitor_elegivel("ELEITOR_001")
    assert not cadastro.is_eleitor_elegivel("ELEITOR_999")
    assert not cadastro.ja_votou("ELEITOR_001")
    assert cadastro.ja_votou("ELEITOR_999")  # não cadastrado não pode votar
    assert all('chave_privada_rsa' not in e for e in servidor.eleitores_cadastrados.values())
    print("✓ Task 2.3: chaves RSA únicas, elegibilidade e controle de unicidade OK")
    print("✓ Task 2.3: servidor armazena apenas chaves públicas dos eleitores")

    try:
        cadastro.cadastrar_eleitor("ELEITOR_001")
        raise AssertionError("Erro: cadastro aceitou eleitor duplicado!")
    except ValueError:
        print("✓ Task 2.3: cadastro duplicado de eleitor rejeitado")

    print("\nResumo do setup:")
    print(f"  - Chave pública conjunta h: {str(h)[:30]}...")
    print(f"  - Total de eleitores elegíveis: {cadastro.total_eleitores_cadastrados()}")
    print(f"  - Eleitores que já votaram: {cadastro.total_eleitores_que_votaram()}")
    print("\n=== FASE 2 CONCLUÍDA COM SUCESSO! ===")
