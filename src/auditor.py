import sys
import json
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from cripto_base import P, calcular_hash_sha256, verificar_assinatura_rsa
from votacao import serializar_canonico, QuadroPublico


class AuditorEleitoral:
    """
    Auditor independente que verifica a integridade de toda a eleicao
    usando exclusivamente dados publicos do Quadro Publico.

    O auditor NAO possui acesso a chaves privadas (x_i) e NAO consegue
    decifrar votos individuais. Sua funcao e verificar:
      1. Cadeia de hashes SHA-256 (integridade do Quadro Publico)
      2. Assinaturas RSA de cada eleitor (autenticidade das cedulas)
      3. Elegibilidade (eleitor esta na lista de cadastrados)
      4. Unicidade (sem voto duplo)
      5. Formato das cedulas (valores no intervalo correto)
      6. Apuracao homomorfica (recalculo independente de C1 e C2)
    """

    def __init__(self, caminho_quadro: str = "quadro_publico.json"):
        self.caminho_quadro = caminho_quadro
        self.quadro = None
        self.configuracao = None
        self.erros = []
        self.avisos = []

    def carregar_quadro(self) -> bool:
        """Carrega o Quadro Publico a partir do arquivo JSON."""
        try:
            self.quadro = QuadroPublico.carregar_json(self.caminho_quadro)
            self.configuracao = self.quadro.configuracao
            return True
        except FileNotFoundError:
            self.erros.append(f"Arquivo {self.caminho_quadro} nao encontrado.")
            return False
        except ValueError as e:
            self.erros.append(str(e))
            return False
        except json.JSONDecodeError as e:
            self.erros.append(f"Erro ao decodificar JSON: {e}")
            return False
        except Exception as e:
            self.erros.append(f"Erro ao carregar quadro: {e}")
            return False

    def verificar_hash_genesis(self) -> bool:
        hash_esperado = calcular_hash_sha256(
            serializar_canonico(self.configuracao)
        )
        if self.quadro.hash_genesis != hash_esperado:
            self.erros.append(
                "Hash de genesis invalido! "
                f"Esperado: {hash_esperado}, Encontrado: {self.quadro.hash_genesis}"
            )
            return False
        return True

    def verificar_cadeia_hashes(self) -> bool:
        anterior = self.quadro.hash_genesis
        todos_ok = True

        for i, bloco in enumerate(self.quadro.blocos):
            if bloco['hash_anterior'] != anterior:
                self.erros.append(
                    f"Bloco {i}: hash_anterior invalido. "
                    f"Esperado: {anterior[:16]}..., Encontrado: {bloco['hash_anterior'][:16]}..."
                )
                todos_ok = False

            dados = {k: v for k, v in bloco.items()
                     if k not in ('hash_anterior', 'hash_atual')}
            hash_calculado = calcular_hash_sha256(
                anterior + serializar_canonico(dados)
            )
            if bloco['hash_atual'] != hash_calculado:
                self.erros.append(
                    f"Bloco {i}: hash_atual invalido (possivel adulteracao). "
                    f"Esperado: {hash_calculado[:16]}..., Encontrado: {bloco['hash_atual'][:16]}..."
                )
                todos_ok = False

            anterior = bloco['hash_atual']

        return todos_ok

    def obter_eleitores_elegiveis(self) -> dict:
        return self.configuracao.get('eleitores_cadastrados', {})

    def verificar_assinaturas_eleitores(self) -> bool:
        todos_ok = True

        for i, bloco in enumerate(self.quadro.blocos):
            id_eleitor = bloco['id_eleitor']
            chave_publica = bloco['chave_publica_eleitor']
            assinatura = bloco['assinatura_eleitor']
            cedula = bloco['cedula']

            conteudo = {'id_eleitor': id_eleitor, 'cedula': cedula}

            try:
                valida = verificar_assinatura_rsa(
                    chave_publica,
                    serializar_canonico(conteudo),
                    assinatura
                )
            except Exception as e:
                self.erros.append(
                    f"Bloco {i} ({id_eleitor}): erro ao verificar assinatura: {e}"
                )
                todos_ok = False
                continue

            if not valida:
                self.erros.append(
                    f"Bloco {i} ({id_eleitor}): assinatura RSA invalida!"
                )
                todos_ok = False

        return todos_ok

    def verificar_elegibilidade(self) -> bool:
        elegiveis = self.obter_eleitores_elegiveis()
        todos_ok = True

        for i, bloco in enumerate(self.quadro.blocos):
            id_eleitor = bloco['id_eleitor']
            if id_eleitor not in elegiveis:
                self.erros.append(
                    f"Bloco {i}: eleitor '{id_eleitor}' nao esta na lista de elegiveis."
                )
                todos_ok = False

        return todos_ok

    def verificar_unicidade(self) -> bool:
        votos_por_eleitor = {}
        todos_ok = True

        for i, bloco in enumerate(self.quadro.blocos):
            id_eleitor = bloco['id_eleitor']
            if id_eleitor in votos_por_eleitor:
                self.erros.append(
                    f"Bloco {i}: eleitor '{id_eleitor}' votou mais de uma vez "
                    f"(primeiro voto no bloco {votos_por_eleitor[id_eleitor]})."
                )
                todos_ok = False
            else:
                votos_por_eleitor[id_eleitor] = i

        return todos_ok

    def verificar_formato_cedulas(self) -> bool:
        candidatos = self.configuracao.get('candidatos', [])
        todos_ok = True

        for i, bloco in enumerate(self.quadro.blocos):
            cedula = bloco['cedula']
            if not isinstance(cedula, list) or len(cedula) != len(candidatos):
                self.erros.append(
                    f"Bloco {i}: cedula malformada (numero de cifras != numero de candidatos)."
                )
                todos_ok = False
                continue

            for j, cifra in enumerate(cedula):
                for chave in ('c1', 'c2'):
                    valor = cifra.get(chave) if isinstance(cifra, dict) else None
                    if not isinstance(valor, int) or not (1 <= valor < P):
                        self.erros.append(
                            f"Bloco {i}, posicao {j}: {chave} fora do intervalo [1, p-1]."
                        )
                        todos_ok = False

        return todos_ok

    def recalcular_apuracao_homomorfica(self) -> dict:
        candidatos = self.configuracao.get('candidatos', [])
        agregados = {}

        for indice, nome in enumerate(candidatos):
            cifras = [
                (b['cedula'][indice]['c1'], b['cedula'][indice]['c2'])
                for b in self.quadro.blocos
            ]

            C1_total = 1
            C2_total = 1
            for c1, c2 in cifras:
                C1_total = (C1_total * c1) % P
                C2_total = (C2_total * c2) % P

            agregados[nome] = {
                'C1': C1_total,
                'C2': C2_total,
                'total_cedulas': len(cifras),
            }

        return agregados

    def executar_auditoria_completa(self) -> dict:
        self.erros = []
        self.avisos = []

        if not self.carregar_quadro():
            return {
                'sucesso': False,
                'erros': self.erros,
                'avisos': self.avisos,
                'total_blocos': 0,
                'apuracao': None,
            }

        total_blocos = len(self.quadro.blocos)

        resultados = {
            'hash_genesis': self.verificar_hash_genesis(),
            'cadeia_hashes': self.verificar_cadeia_hashes(),
            'assinaturas': self.verificar_assinaturas_eleitores(),
            'elegibilidade': self.verificar_elegibilidade(),
            'unicidade': self.verificar_unicidade(),
            'formato_cedulas': self.verificar_formato_cedulas(),
        }

        apuracao = self.recalcular_apuracao_homomorfica()

        todos_ok = all(resultados.values()) and len(self.erros) == 0

        return {
            'sucesso': todos_ok,
            'erros': self.erros,
            'avisos': self.avisos,
            'total_blocos': total_blocos,
            'resultados_detalhados': resultados,
            'apuracao': apuracao,
            'configuracao': {
                'candidatos': self.configuracao.get('candidatos', []),
                'total_eleitores_elegiveis': len(self.obter_eleitores_elegiveis()),
            },
        }


if __name__ == "__main__":
    caminho = sys.argv[1] if len(sys.argv) > 1 else "quadro_publico.json"
    auditor = AuditorEleitoral(caminho)
    relatorio = auditor.executar_auditoria_completa()

    print("=" * 60)
    print("RELATORIO DE AUDITORIA INDEPENDENTE")
    print("=" * 60)

    if not relatorio['sucesso'] and relatorio['total_blocos'] == 0:
        print()
        print("ERRO: Nao foi possivel carregar o quadro publico.")
        for erro in relatorio['erros']:
            print(f"  - {erro}")
        sys.exit(1)

    print()
    print(f"Total de votos no Quadro Publico: {relatorio['total_blocos']}")
    print(f"Candidatos: {', '.join(relatorio['configuracao']['candidatos'])}")
    print(f"Eleitores elegiveis cadastrados: {relatorio['configuracao']['total_eleitores_elegiveis']}")

    print()
    print("--- Verificacoes Realizadas ---")
    checks = [
        ('Hash de Genesis', relatorio['resultados_detalhados']['hash_genesis']),
        ('Cadeia de Hashes (Integridade)', relatorio['resultados_detalhados']['cadeia_hashes']),
        ('Assinaturas RSA dos Eleitores', relatorio['resultados_detalhados']['assinaturas']),
        ('Elegibilidade dos Eleitores', relatorio['resultados_detalhados']['elegibilidade']),
        ('Unicidade (sem voto duplo)', relatorio['resultados_detalhados']['unicidade']),
        ('Formato das Cedulas', relatorio['resultados_detalhados']['formato_cedulas']),
    ]

    todos_passaram = True
    for nome, ok in checks:
        status = "PASSOU" if ok else "FALHOU"
        print(f"  {nome}: {status}")
        if not ok:
            todos_passaram = False

    if relatorio['erros']:
        print()
        print("--- Erros Encontrados ---")
        for erro in relatorio['erros']:
            print(f"  - {erro}")

    if relatorio['apuracao']:
        print()
        print("--- Apuracao Homomorfica (Recalculo Independente) ---")
        print("  (C1 e C2 sao valores publicos; M so pode ser extraido com as autoridades)")
        for nome, dados in relatorio['apuracao'].items():
            print(f"  {nome}: C1={dados['C1']}, C2={dados['C2']}, cedulas={dados['total_cedulas']}")

    print()
    print("=" * 60)
    if todos_passaram:
        print("AUDITORIA CONCLUIDA: Quadro Publico integro e verificavel.")
    else:
        print("AUDITORIA FALHOU: Foram detectados problemas no Quadro Publico.")
    print("=" * 60)
