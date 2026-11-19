import sys
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

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

    print("\n=== ATAQUES QUE DEVEM SER BLOQUEADOS ===\n")

    def tentar(descricao, pacote):
        try:
            servidor.receber_voto(pacote)
            print(f" ✗ {descricao}: ACEITO (erro!)")
            raise AssertionError(descricao)
        except ValueError as e:
            print(f" ✓ {descricao}: {e}")

    tentar("Votar duas vezes", criar_eleitor("ELEITOR_001").votar("Bob"))

    intruso = Eleitor("INTRUSO", *gerar_par_chaves_rsa(), h, CANDIDATOS)
    tentar("Eleitor não cadastrado", intruso.votar("Bob"))

    pacote = criar_eleitor("ELEITOR_006").votar("Bob")
    pacote['cedula'][0], pacote['cedula'][1] = pacote['cedula'][1], pacote['cedula'][0]
    tentar("Cédula adulterada após assinatura", pacote)

    falso = Eleitor("ELEITOR_006", *gerar_par_chaves_rsa(), h, CANDIDATOS)
    tentar("Assinatura com chave errada", falso.votar("Bob"))

    pacote = criar_eleitor("ELEITOR_006").votar("Bob")
    pacote['cedula'] = pacote['cedula'][:2]
    tentar("Cédula com cifras faltando", pacote)

    print("\n=== VALIDAÇÕES DO QUADRO ===\n")

    # Encadeamento: cada bloco aponta para o hash do anterior
    anterior = servidor.quadro.hash_genesis
    for bloco in servidor.quadro.blocos:
        dados = {k: v for k, v in bloco.items() if k not in ('hash_anterior', 'hash_atual')}
        assert bloco['hash_anterior'] == anterior
        assert bloco['hash_atual'] == calcular_hash_sha256(anterior + serializar_canonico(dados))
        anterior = bloco['hash_atual']
    print(f"✓ Cadeia de {len(servidor.quadro.blocos)} blocos íntegra")

    # Ida e volta em JSON preserva tudo (inclusive inteiros de 2048 bits)
    caminho = "quadro_publico.json"
    servidor.quadro.salvar_json(caminho)
    recarregado = QuadroPublico.carregar_json(caminho)
    assert recarregado.para_dict() == servidor.quadro.para_dict()
    print(f"✓ Quadro salvo em {caminho} e recarregado sem perdas")

    # Sanidade: apuração rápida com a soma das x_i (só para TESTE; na Fase 4
    # isso será feito de forma distribuída, sem ninguém conhecer x_total)
    from cripto_base import somar_cifras_homomorficamente, exp_mod, remover_mascara_elgamal, decifrar_logaritmo_discreto
    x_total = sum(a.x_i for a in autoridades)
    for i, nome in enumerate(CANDIDATOS):
        cifras = [(b['cedula'][i]['c1'], b['cedula'][i]['c2']) for b in servidor.quadro.blocos]
        C1, C2 = somar_cifras_homomorficamente(cifras)
        M = decifrar_logaritmo_discreto(remover_mascara_elgamal(C2, exp_mod(C1, x_total, P)), len(cifras))
        esperado = sum(1 for c in escolhas.values() if c == nome)
        assert M == esperado
        print(f"✓ {nome}: {M} voto(s) (esperado {esperado})")

    print("\n=== FASE 3 CONCLUÍDA COM SUCESSO! ===")
