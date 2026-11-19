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

    # TASK 4.1: Multiplicação Homomórfica dos Votos no Servidor (C1 e C2)

    def agregar_cifras_homomorficas(self) -> dict:
        """
        [Task 4.1] Multiplica os componentes c1 e c2 de todos os votos
        para cada candidato, gerando os acumulados (C1, C2).
        Fórmula: C1 = prod(c1_j) mod p = g^(sum r_j) mod p
                 C2 = prod(c2_j) mod p = g^(sum m_j) * h^(sum r_j) mod p
        """
        total_cedulas = len(self.quadro.blocos)
        if total_cedulas == 0:
            raise ValueError("Não há votos registrados no Quadro Público para apurar.")

        agregados = {}
        for indice, nome in enumerate(self.candidatos):
            cifras = [(b['cedula'][indice]['c1'], b['cedula'][indice]['c2']) for b in self.quadro.blocos]
            C1, C2 = somar_cifras_homomorficamente(cifras, self.P)
            agregados[nome] = {'C1': C1, 'C2': C2, 'total_cedulas': total_cedulas}

        return agregados

    # TASK 4.2: Rotina de Decifração Parcial das Autoridades Eleitorais

    def coletar_decifracoes_parciais(self, agregados: dict, autoridades_participantes: list = None) -> dict:
        """
        [Task 4.2] Coleta a decifração parcial d_i de cada autoridade para cada candidato.
        Fórmula: d_i = C1^(x_i) mod p
        Cada autoridade usa seu próprio segredo privado x_i sem nunca revelá-lo.
        """
        if autoridades_participantes is None:
            autoridades_participantes = self.autoridades

        decifracoes = {nome: [] for nome in self.candidatos}

        for auth in autoridades_participantes:
            for nome in self.candidatos:
                C1 = agregados[nome]['C1']
                # Chama o método da autoridade que calcula d_i = C1^(x_i) mod p
                d_i = auth.calcular_decifracao_parcial(C1, self.P)
                decifracoes[nome].append({
                    'autoridade_id': auth.id,
                    'd_i': d_i
                })

        return decifracoes

    # TASK 4.3: Recombinação da Máscara, Extração de g^M e Logaritmo Discreto

    def recombinar_e_decifrar(self, agregados: dict, decifracoes: dict) -> dict:
        """
        [Task 4.3] Para cada candidato:
        1. Multiplica os d_i das autoridades para reconstruir a máscara conjunta:
           S = prod(d_i) mod p = prod(C1^(x_i)) = C1^(sum x_i) = h^(sum r) mod p
        2. Isola g^M multiplicando C2 pelo inverso modular de S:
           g^M = C2 * S^(-1) mod p
        3. Recupera M (total de votos) através de busca exaustiva do logaritmo discreto.
        """
        total_cedulas = len(self.quadro.blocos)
        resultado_final = {}

        for nome in self.candidatos:
            C1 = agregados[nome]['C1']
            C2 = agregados[nome]['C2']
            lista_d_i = [item['d_i'] for item in decifracoes[nome]]

            # 1. Reconstrói a máscara conjunta: S = prod(d_i) mod p
            S = 1
            for d in lista_d_i:
                S = (S * d) % self.P

            # 2. Isola g^M = C2 * S^(-1) mod p
            g_M = remover_mascara_elgamal(C2, S, self.P)

            # 3. Busca exaustiva do logaritmo discreto
            # O número máximo de votos que um candidato pode receber é o total de cédulas
            votos = decifrar_logaritmo_discreto(
                g_elevado_M=g_M,
                max_votos_possiveis=total_cedulas,
                p=self.P,
                g=self.G
            )
            resultado_final[nome] = votos

        return resultado_final

    # COORDENAÇÃO COMPLETA DA APURAÇÃO (Pipeline das Tasks 4.1 a 4.3)

    def executar_apuracao(self, autoridades_participantes: list = None, verbose: bool = True) -> dict:
        """
        Executa o fluxo completo e ordenado da Apuração Homomórfica:
        Passo 1: Agregação homomórfica (Task 4.1)
        Passo 2: Coleta de decifrações parciais (Task 4.2)
        Passo 3: Recombinação e extração de resultados (Task 4.3)
        """
        if autoridades_participantes is None:
            autoridades_participantes = self.autoridades

        total_cedulas = len(self.quadro.blocos)
        if total_cedulas == 0:
            raise ValueError("Não há votos registrados no Quadro Público para apurar.")

        if verbose:
            print("\n" + "="*55)
            print(f"🏛️  INICIANDO APURAÇÃO HOMOMÓRFICA ({total_cedulas} votos no Quadro)")
            print("="*55)

        # 1. Agregação Homomórfica (Task 4.1)
        agregados = self.agregar_cifras_homomorficas()
        if verbose:
            for nome in self.candidatos:
                print(f" -> Candidato '{nome}': C1 e C2 homomórficos calculados.")

        # 2. Decifrações Parciais (Task 4.2)
        if verbose:
            print(f"\n[Coleta de Decifrações Parciais: {len(autoridades_participantes)} autoridade(s)]")
        decifracoes = self.coletar_decifracoes_parciais(agregados, autoridades_participantes)
        if verbose:
            for auth in autoridades_participantes:
                print(f" -> Autoridade #{auth.id} forneceu suas decifrações parciais d_i.")

        # 3. Recombinação e Decifração (Task 4.3)
        if verbose:
            print("\n[Recombinação das Máscaras e Extração dos Totais]")
        resultado = self.recombinar_e_decifrar(agregados, decifracoes)

        if verbose:
            print("\n" + "-"*35)
            print("🏆 RESULTADO FINAL DA ELEIÇÃO:")
            print("-"*35)
            for nome, qtd in sorted(resultado.items(), key=lambda item: item[1], reverse=True):
                print(f"  • {nome:10s}: {qtd} voto(s)")
            print("="*55 + "\n")

        return resultado


# DEMONSTRAÇÕES E VALIDAÇÕES DA FASE 4
if __name__ == "__main__":
    from setup_eleicao import executar_setup_fase2
    from votacao import ServidorEleicao, Eleitor

    print("=== CONFIGURANDO ELEIÇÃO COMPLETA PARA DEMONSTRAÇÃO (FASE 4) ===\n")
    CANDIDATOS = ["Alice", "Bob", "Carol"]

    # 1. Setup com 3 Autoridades Eleitorais e chave conjunta h
    autoridades, servidor_setup, cadastro, h = executar_setup_fase2()
    servidor = ServidorEleicao(servidor_setup, CANDIDATOS)

    # 2. Votação de 5 eleitores
    # Distribuição planejada: Alice = 3, Bob = 1, Carol = 1
    escolhas_eleitores = {
        "ELEITOR_001": "Alice",
        "ELEITOR_002": "Bob",
        "ELEITOR_003": "Alice",
        "ELEITOR_004": "Carol",
        "ELEITOR_005": "Alice",
    }

    print("-> Registrando votos no Quadro Público...")
    for id_eleitor, escolha in escolhas_eleitores.items():
        eleitor = Eleitor(
            id_eleitor,
            cadastro.obter_chave_privada_rsa(id_eleitor),
            cadastro.obter_chave_publica_rsa(id_eleitor),
            h, CANDIDATOS
        )
        pacote_voto = eleitor.votar(escolha)
        servidor.receber_voto(pacote_voto)

    print(f"-> {len(servidor.quadro.blocos)} votos registrados com sucesso no Quadro Público.\n")

    # CENÁRIO 1: Apuração normal com TODAS as autoridades (Tasks 4.1 a 4.3)
    print("--- [CENÁRIO 1] Apuração Oficial (Todas as 3 Autoridades Presentes) ---")
    apurador = ApuradorEleicao(servidor.quadro, autoridades)
    resultado = apurador.executar_apuracao()

    esperado = {"Alice": 3, "Bob": 1, "Carol": 1}
    assert resultado == esperado, f"Erro: Esperado {esperado}, obtido {resultado}"
    print("✓ CENÁRIO 1 VALIDADO: Contagem exata sem violar o sigilo de nenhuma cédula!\n")

    # CENÁRIO 2 (OBRIGATÓRIO NA APRESENTAÇÃO AO VIVO):
    # Tentativa de apuração sem a participação de todas as autoridades
    print("--- [CENÁRIO 2] Demonstração Obrigatória: Falha com Autoridade Faltante ---")
    # Tentamos apurar fornecendo apenas 2 das 3 autoridades (Autoridade 3 ausente)
    autoridades_incompletas = autoridades[:2]
    print(f"-> Tentando apurar com apenas {len(autoridades_incompletas)} de {len(autoridades)} autoridades...")

    try:
        apurador_incompleto = ApuradorEleicao(servidor.quadro, autoridades_incompletas)
        resultado_invalido = apurador_incompleto.executar_apuracao(verbose=False)
        print("✗ ERRO GRAVE: A apuração concluiu sem todas as autoridades!")
        raise AssertionError("Apuração incompleta deveria ter falhado matematicamente!")
    except ValueError as e:
        print("✓ SUCESSO: A apuração falhou conforme previsto pela criptografia!")
        print(f"  Motivo da falha matemática: {e}")
        print("  Explicação: A máscara combinada não atinge h^R, gerando ruído aleatório no logaritmo discreto.\n")

    # CENÁRIO 3: Autoridade maliciosa fornecendo d_i corrompido
    print("--- [CENÁRIO 3] Demonstração: Autoridade Desonesta com d_i Adulterado ---")
    class AutoridadeMaliciosa(AutoridadeEleitoral):
        def calcular_decifracao_parcial(self, C1: int, p: int = P) -> int:
            # Retorna um valor falso aleatório
            return 999999999999999

    autoridades_com_sabotador = [autoridades[0], autoridades[1], AutoridadeMaliciosa(id_autoridade=3)]

    try:
        apurador_sabotado = ApuradorEleicao(servidor.quadro, autoridades_com_sabotador)
        apurador_sabotado.executar_apuracao(verbose=False)
        print("✗ ERRO: Apuração com sabotador não falhou!")
    except ValueError as e:
        print("✓ SUCESSO: Sabotagem detectada! O resultado não pôde ser decifrado.")
        print(f"  Erro capturado: {e}\n")

    print("=== TODAS AS VALIDAÇÕES DA FASE 4 FORAM CONCLUÍDAS COM SUCESSO! ===")
