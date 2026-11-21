"""
CLI unificada do Sistema de Votação Eletrônica Seguro (Task 5.4).

Cada subcomando é uma etapa da eleição. O estado fica numa pasta (padrão: ./eleicao):

    eleicao/
    ├── publico/                      <- o que qualquer pessoa pode ver
    │   ├── quadro_publico.json       (quadro encadeado; é o único arquivo que o auditor lê)
    │   └── estado.json               (votação aberta/encerrada)
    └── privado/                      <- segredos de cada entidade (simulação local)
        ├── autoridade_N.json         (x_i da autoridade N)
        ├── servidor.json             (chave RSA privada do servidor, usada nos recibos)
        └── eleitores/ID.json         (chave RSA privada + recibo de cada eleitor)

Uso rápido:
    python3 src/cli.py setup
    python3 src/cli.py votar ELEITOR_001 Alice
    python3 src/cli.py votar ELEITOR_001 Bob      # rejeitado (voto duplo)
    python3 src/cli.py auditar
    python3 src/cli.py encerrar
    python3 src/cli.py adulterar                  # simula fraude no quadro
    python3 src/cli.py auditar                    # auditor detecta
    python3 src/cli.py restaurar
    python3 src/cli.py apurar --sem-autoridade 3  # falha
    python3 src/cli.py apurar                     # resultado
    python3 src/cli.py demo                       # roda tudo isso automaticamente
"""
import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

_SRC_DIR = Path(__file__).resolve().parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from cripto_base import P, G, verificar_assinatura_rsa
from setup_eleicao import executar_setup_fase2, ServidorVotacao, AutoridadeEleitoral
from votacao import QuadroPublico, ServidorEleicao, Eleitor, serializar_canonico
from apuracao import ApuradorEleicao
from auditor import AuditorEleitoral

CANDIDATOS_PADRAO = ["Alice", "Bob", "Carol"]


# ---------------------------------------------------------------------------
# Caminhos e persistência
# ---------------------------------------------------------------------------

class Pastas:
    def __init__(self, base: str):
        self.base = Path(base)
        self.publico = self.base / "publico"
        self.privado = self.base / "privado"
        self.eleitores = self.privado / "eleitores"
        self.quadro = self.publico / "quadro_publico.json"
        self.quadro_original = self.publico / "quadro_publico.original.json"
        self.estado = self.publico / "estado.json"
        self.servidor = self.privado / "servidor.json"

    def autoridade(self, n: int) -> Path:
        return self.privado / f"autoridade_{n}.json"


def _ler(caminho: Path):
    with open(caminho, "r", encoding="utf-8") as f:
        return json.load(f)


def _gravar(caminho: Path, dados):
    caminho.parent.mkdir(parents=True, exist_ok=True)
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(dados, f, indent=2, ensure_ascii=False)


def _exigir_eleicao(pastas: Pastas):
    if not pastas.quadro.exists():
        raise SystemExit(f"Nenhuma eleição em '{pastas.base}'. Rode primeiro: python3 src/cli.py setup")


def _carregar_autoridades(pastas: Pastas) -> list:
    autoridades = []
    for arq in sorted(pastas.privado.glob("autoridade_*.json"),
                      key=lambda a: int(a.stem.split("_")[1])):
        dados = _ler(arq)
        a = AutoridadeEleitoral(dados["id"])
        a.x_i = dados["x_i"]
        a.h_i = dados["h_i"]
        autoridades.append(a)
    return autoridades


def _carregar_servidor(pastas: Pastas) -> ServidorEleicao:
    """
    Reconstrói o servidor a partir dos arquivos. O que é público vem do Quadro
    (configuração e blocos); o único segredo do servidor é sua chave RSA de recibos.
    Quem já votou é deduzido do próprio quadro, então o controle de unicidade
    não depende de nenhum estado "escondido".
    """
    quadro = QuadroPublico.carregar_json(str(pastas.quadro))
    cfg = quadro.configuracao

    setup = ServidorVotacao()
    setup.chaves_publicas_parciais = cfg["h_parciais"]
    setup.h_conjunta = cfg["h"]
    setup.eleitores_cadastrados = {
        id_e: {"chave_publica_rsa": d["chave_publica_rsa"], "votou": False}
        for id_e, d in cfg["eleitores_cadastrados"].items()
    }
    for bloco in quadro.blocos:
        setup.eleitores_cadastrados[bloco["id_eleitor"]]["votou"] = True

    srv = ServidorEleicao.__new__(ServidorEleicao)  # evita gerar novas chaves/quadro no __init__
    srv.servidor_setup = setup
    srv.candidatos = cfg["candidatos"]
    srv.chave_privada_rsa = _ler(pastas.servidor)["chave_privada_rsa"]
    srv.chave_publica_rsa = cfg["chave_publica_servidor"]
    srv.quadro = quadro
    return srv


def _votacao_encerrada(pastas: Pastas) -> bool:
    return _ler(pastas.estado).get("encerrada", False)


def _resumo(n, limite=18):
    s = str(n)
    return s if len(s) <= limite else s[:limite] + "..."


# ---------------------------------------------------------------------------
# Subcomandos
# ---------------------------------------------------------------------------

def cmd_setup(args) -> int:
    pastas = Pastas(args.dir)
    if pastas.base.exists() and any(pastas.base.iterdir()):
        if not args.forcar:
            print(f"✗ A pasta '{pastas.base}' já tem uma eleição. Use --forcar para recriar.")
            return 1
        shutil.rmtree(pastas.base)
    if args.autoridades < 3:
        print("✗ A especificação exige pelo menos 3 autoridades.")
        return 1
    if len(args.candidatos) < 2:
        print("✗ A eleição precisa de pelo menos 2 candidatos.")
        return 1

    ids = [f"ELEITOR_{i:03d}" for i in range(1, args.eleitores + 1)]
    autoridades, setup, cadastro, h = executar_setup_fase2(args.autoridades, ids)
    servidor = ServidorEleicao(setup, args.candidatos)

    # Segredos de cada entidade em arquivos separados
    for a in autoridades:
        _gravar(pastas.autoridade(a.id), {"id": a.id, "x_i": a.x_i, "h_i": a.h_i})
    for id_e in ids:
        _gravar(pastas.eleitores / f"{id_e}.json", {
            "id_eleitor": id_e,
            "chave_privada_rsa": cadastro.obter_chave_privada_rsa(id_e),
            "chave_publica_rsa": cadastro.obter_chave_publica_rsa(id_e),
        })
    _gravar(pastas.servidor, {"chave_privada_rsa": servidor.chave_privada_rsa})

    # Parte pública
    pastas.publico.mkdir(parents=True, exist_ok=True)
    servidor.quadro.salvar_json(str(pastas.quadro))
    _gravar(pastas.estado, {"encerrada": False})

    print(f"✓ Eleição criada em '{pastas.base}'")
    print(f"  Candidatos : {', '.join(args.candidatos)}")
    print(f"  Autoridades: {args.autoridades} (cada uma guarda só o seu x_i)")
    print(f"  Eleitores  : {', '.join(ids)}")
    print(f"  Chave pública conjunta h = {_resumo(h)}")
    return 0


def cmd_votar(args) -> int:
    pastas = Pastas(args.dir)
    _exigir_eleicao(pastas)

    if _votacao_encerrada(pastas):
        print("✗ REJEITADO: a votação já foi encerrada.")
        return 1

    servidor = _carregar_servidor(pastas)
    arq_eleitor = pastas.eleitores / f"{args.eleitor}.json"
    if arq_eleitor.exists():
        chaves = _ler(arq_eleitor)
        priv, pub = chaves["chave_privada_rsa"], chaves["chave_publica_rsa"]
    else:
        # Sem cadastro => não tem chave registrada. Gera uma chave qualquer só para
        # mostrar que o servidor recusa quem não está na lista de elegibilidade.
        from cripto_base import gerar_par_chaves_rsa
        priv, pub = gerar_par_chaves_rsa()
        chaves = None

    cfg = servidor.quadro.configuracao
    eleitor = Eleitor(args.eleitor, priv, pub, cfg["h"], cfg["candidatos"])

    try:
        pacote = eleitor.votar(args.candidato)
        recibo = servidor.receber_voto(pacote)
    except ValueError as e:
        print(f"✗ {e}")
        return 1

    servidor.quadro.salvar_json(str(pastas.quadro))
    valido = eleitor.verificar_recibo(recibo, servidor.chave_publica_rsa)
    chaves["recibo"] = recibo
    _gravar(arq_eleitor, chaves)

    print(f"✓ {args.eleitor} votou (voto cifrado; ninguém, nem o servidor, vê a escolha).")
    print(f"  Bloco #{recibo['dados']['indice']}  hash={_resumo(recibo['dados']['hash_bloco'], 24)}")
    print(f"  Recibo assinado pelo servidor válido? {valido}")
    return 0


def cmd_verificar_recibo(args) -> int:
    """Verificabilidade individual: o recibo é autêntico e o bloco consta no quadro público?"""
    pastas = Pastas(args.dir)
    _exigir_eleicao(pastas)
    arq = pastas.eleitores / f"{args.eleitor}.json"
    if not arq.exists() or "recibo" not in _ler(arq):
        print(f"✗ {args.eleitor} não possui recibo (ainda não votou).")
        return 1

    recibo = _ler(arq)["recibo"]
    quadro = QuadroPublico.carregar_json(str(pastas.quadro))
    chave_srv = quadro.configuracao["chave_publica_servidor"]

    assinatura_ok = verificar_assinatura_rsa(
        chave_srv, serializar_canonico(recibo["dados"]), recibo["assinatura_servidor"])
    idx = recibo["dados"]["indice"]
    consta = (idx < len(quadro.blocos)
              and quadro.blocos[idx]["hash_atual"] == recibo["dados"]["hash_bloco"]
              and quadro.blocos[idx]["id_eleitor"] == args.eleitor)

    print(f"Assinatura do servidor no recibo: {'VÁLIDA' if assinatura_ok else 'INVÁLIDA'}")
    print(f"Cédula consta no quadro público (bloco #{idx}, mesmo hash): {'SIM' if consta else 'NÃO'}")
    return 0 if (assinatura_ok and consta) else 1


def cmd_encerrar(args) -> int:
    pastas = Pastas(args.dir)
    _exigir_eleicao(pastas)
    if _votacao_encerrada(pastas):
        print("A votação já estava encerrada.")
        return 0
    _gravar(pastas.estado, {"encerrada": True})
    n = len(QuadroPublico.carregar_json(str(pastas.quadro)).blocos)
    print(f"✓ Votação encerrada com {n} cédula(s) no quadro. Agora a apuração é permitida.")
    return 0


def cmd_status(args) -> int:
    pastas = Pastas(args.dir)
    _exigir_eleicao(pastas)
    quadro = QuadroPublico.carregar_json(str(pastas.quadro))
    cfg = quadro.configuracao
    votaram = {b["id_eleitor"] for b in quadro.blocos}
    print(f"Candidatos : {', '.join(cfg['candidatos'])}")
    print(f"Autoridades: {len(cfg['h_parciais'])}")
    print(f"Votação    : {'ENCERRADA' if _votacao_encerrada(pastas) else 'ABERTA'}")
    print(f"Cédulas no quadro: {len(quadro.blocos)}")
    for id_e in cfg["eleitores_cadastrados"]:
        print(f"  {id_e}: {'votou' if id_e in votaram else 'não votou'}")
    return 0


def cmd_auditar(args) -> int:
    """Roda o auditor independente, que lê APENAS o arquivo público do quadro."""
    pastas = Pastas(args.dir)
    caminho = Path(args.arquivo) if args.arquivo else pastas.quadro
    if not caminho.exists():
        print(f"✗ Arquivo '{caminho}' não encontrado.")
        return 1

    auditor = AuditorEleitoral(str(caminho))
    rel = auditor.executar_auditoria_completa()

    if not rel["sucesso"] and rel["total_blocos"] == 0:
        print("✗ Não foi possível carregar o quadro público:")
        for e in rel["erros"]:
            print(f"  - {e}")
        return 2

    print(f"AUDITORIA do quadro '{caminho}' ({rel['total_blocos']} cédulas)")
    nomes = [
        ("hash_genesis", "Hash de gênese"),
        ("cadeia_hashes", "Cadeia de hashes"),
        ("assinaturas", "Assinaturas RSA dos eleitores"),
        ("elegibilidade", "Elegibilidade"),
        ("unicidade", "Unicidade (sem voto duplo)"),
        ("formato_cedulas", "Formato das cédulas"),
    ]
    for chave, nome in nomes:
        ok = rel["resultados_detalhados"][chave]
        print(f"  [{'OK' if ok else 'FALHOU'}] {nome}")

    if rel["erros"]:
        print("\nProblemas detectados:")
        for e in rel["erros"]:
            print(f"  - {e}")

    if rel["apuracao"]:
        print("\nProduto homomórfico recalculado (C1, C2 por candidato):")
        for nome, d in rel["apuracao"].items():
            print(f"  {nome}: C1={_resumo(d['C1'])}  C2={_resumo(d['C2'])}")

    if rel["sucesso"]:
        print("\n✓ ELEIÇÃO VÁLIDA: o quadro público é íntegro e verificável.")
        return 0
    print("\n✗ ELEIÇÃO ADULTERADA: o auditor encontrou inconsistências.")
    return 2


def cmd_adulterar(args) -> int:
    """
    Simula um administrador malicioso que tenta inflar os votos de um candidato:
    multiplica c2 por g, o que equivale a somar +1 ao voto cifrado. Os hashes e a
    assinatura do eleitor NÃO são recalculados (o atacante não tem como assinar).
    """
    pastas = Pastas(args.dir)
    _exigir_eleicao(pastas)
    if pastas.quadro_original.exists():
        print("✗ O quadro já está adulterado. Use 'restaurar' antes.")
        return 1

    dados = _ler(pastas.quadro)
    if not dados["blocos"]:
        print("✗ O quadro está vazio, não há o que adulterar.")
        return 1
    idx = args.bloco if args.bloco is not None else len(dados["blocos"]) // 2
    if not (0 <= idx < len(dados["blocos"])):
        print(f"✗ Bloco inválido (0..{len(dados['blocos']) - 1}).")
        return 1
    cand = dados["configuracao"]["candidatos"]
    if not (0 <= args.candidato < len(cand)):
        print(f"✗ Índice de candidato inválido (0..{len(cand) - 1}).")
        return 1

    shutil.copyfile(pastas.quadro, pastas.quadro_original)
    cifra = dados["blocos"][idx]["cedula"][args.candidato]
    antigo = cifra["c2"]
    cifra["c2"] = (cifra["c2"] * G) % P
    _gravar(pastas.quadro, dados)

    print(f"⚠ ADULTERAÇÃO simulada: bloco #{idx}, cifra do candidato '{cand[args.candidato]}'")
    print(f"  c2 antes : {_resumo(antigo)}")
    print(f"  c2 depois: {_resumo(cifra['c2'])}  (equivale a +1 voto escondido)")
    print("  Backup do quadro original em publico/quadro_publico.original.json")
    return 0


def cmd_restaurar(args) -> int:
    pastas = Pastas(args.dir)
    if not pastas.quadro_original.exists():
        print("Nada a restaurar: o quadro não foi adulterado.")
        return 0
    shutil.move(pastas.quadro_original, pastas.quadro)
    print("✓ Quadro original restaurado.")
    return 0


def cmd_apurar(args) -> int:
    pastas = Pastas(args.dir)
    _exigir_eleicao(pastas)

    # Justiça: nenhum resultado parcial antes do encerramento
    if not _votacao_encerrada(pastas):
        print("✗ A votação ainda está aberta. Rode 'encerrar' antes de apurar (justiça: sem resultado parcial).")
        return 1

    quadro = QuadroPublico.carregar_json(str(pastas.quadro))
    autoridades = _carregar_autoridades(pastas)
    total = len(autoridades)

    participantes = [a for a in autoridades if a.id not in set(args.sem_autoridade or [])]
    ausentes = total - len(participantes)
    if ausentes:
        print(f"-> Apurando com {len(participantes)} de {total} autoridades "
              f"(ausente(s): {sorted(set(args.sem_autoridade))})")

    try:
        resultado = ApuradorEleicao(quadro, participantes).executar_apuracao()
    except ValueError as e:
        print("✗ APURAÇÃO FALHOU:", e)
        if ausentes:
            print("  Sem o d_i de todas as autoridades a máscara h^R não é removida;")
            print("  C2·S⁻¹ vira um número aleatório e nenhum total g^M é encontrado.")
        return 2

    if ausentes:
        # Não deveria acontecer; se acontecer é um bug de segurança.
        print("✗ ERRO GRAVE: a apuração terminou sem todas as autoridades!")
        return 3
    return 0


# ---------------------------------------------------------------------------
# Demo: roteiro completo para a apresentação
# ---------------------------------------------------------------------------

def cmd_demo(args) -> int:
    base = args.dir if args.dir != "eleicao" else tempfile.mkdtemp(prefix="eleicao_demo_")
    comum = {"dir": base}
    passo = [0]

    def titulo(texto):
        passo[0] += 1
        print("\n" + "=" * 66)
        print(f" PASSO {passo[0]}: {texto}")
        print("=" * 66)
        if args.pausa:
            input("(Enter para executar) ")

    def rodar(fn, esperado=0, **kw):
        rc = fn(SimpleNamespace(**comum, **kw))
        if rc != esperado:
            print(f"\n✗ DEMO INTERROMPIDA: código de saída {rc}, esperado {esperado}.")
            raise SystemExit(1)

    print(f"Pasta da demo: {base}")

    titulo("Configuração: 3 autoridades, 5 eleitores, 3 candidatos")
    rodar(cmd_setup, autoridades=3, eleitores=5, candidatos=CANDIDATOS_PADRAO, forcar=True)

    titulo("Votação: 5 eleitores votam (cédulas cifradas)")
    escolhas = [("ELEITOR_001", "Alice"), ("ELEITOR_002", "Bob"), ("ELEITOR_003", "Alice"),
                ("ELEITOR_004", "Carol"), ("ELEITOR_005", "Alice")]
    for id_e, cand in escolhas:
        rodar(cmd_votar, eleitor=id_e, candidato=cand)

    titulo("Verificabilidade individual: ELEITOR_001 confere seu recibo")
    rodar(cmd_verificar_recibo, eleitor="ELEITOR_001")

    titulo("Ataque: ELEITOR_001 tenta votar uma segunda vez (deve ser rejeitado)")
    rodar(cmd_votar, esperado=1, eleitor="ELEITOR_001", candidato="Bob")

    titulo("Ataque: eleitor não cadastrado tenta votar (deve ser rejeitado)")
    rodar(cmd_votar, esperado=1, eleitor="INTRUSO", candidato="Bob")

    titulo("Auditoria independente antes do encerramento (deve passar)")
    rodar(cmd_auditar, arquivo=None)

    titulo("Encerramento da votação")
    rodar(cmd_encerrar)

    titulo("Ataque: administrador adultera uma cédula no quadro público")
    rodar(cmd_adulterar, bloco=2, candidato=1)

    titulo("O auditor detecta a adulteração (deve FALHAR)")
    rodar(cmd_auditar, esperado=2, arquivo=None)

    titulo("Restaura o quadro original")
    rodar(cmd_restaurar)

    titulo("Ataque: apuração sem a autoridade 3 (deve falhar)")
    rodar(cmd_apurar, esperado=2, sem_autoridade=[3])

    titulo("Apuração oficial com todas as autoridades")
    rodar(cmd_apurar, sem_autoridade=None)

    titulo("Auditoria final")
    rodar(cmd_auditar, arquivo=None)

    print("\n✓ DEMONSTRAÇÃO COMPLETA.")
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def montar_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py", description="Sistema de Votação Eletrônica Seguro (ElGamal + chave conjunta + quadro público)")
    parser.add_argument("--dir", default="eleicao", help="pasta com o estado da eleição (padrão: eleicao)")
    sub = parser.add_subparsers(dest="comando", required=True)

    p = sub.add_parser("setup", help="cria autoridades, chave conjunta h, eleitores e quadro vazio")
    p.add_argument("--autoridades", type=int, default=3)
    p.add_argument("--eleitores", type=int, default=5)
    p.add_argument("--candidatos", nargs="+", default=CANDIDATOS_PADRAO)
    p.add_argument("--forcar", action="store_true", help="apaga uma eleição existente")
    p.set_defaults(fn=cmd_setup)

    p = sub.add_parser("votar", help="um eleitor vota em um candidato")
    p.add_argument("eleitor")
    p.add_argument("candidato")
    p.set_defaults(fn=cmd_votar)

    p = sub.add_parser("verificar-recibo", help="o eleitor confere seu recibo contra o quadro público")
    p.add_argument("eleitor")
    p.set_defaults(fn=cmd_verificar_recibo)

    sub.add_parser("encerrar", help="encerra a votação").set_defaults(fn=cmd_encerrar)
    sub.add_parser("status", help="mostra o estado da eleição").set_defaults(fn=cmd_status)

    p = sub.add_parser("auditar", help="roda o auditor independente sobre o quadro público")
    p.add_argument("--arquivo", help="auditar outro arquivo de quadro (padrão: o da eleição)")
    p.set_defaults(fn=cmd_auditar)

    p = sub.add_parser("adulterar", help="[ataque] altera uma cédula no quadro público")
    p.add_argument("--bloco", type=int, help="índice do bloco (padrão: o do meio)")
    p.add_argument("--candidato", type=int, default=0, help="índice do candidato cuja cifra será alterada")
    p.set_defaults(fn=cmd_adulterar)

    sub.add_parser("restaurar", help="desfaz a adulteração simulada").set_defaults(fn=cmd_restaurar)

    p = sub.add_parser("apurar", help="apuração homomórfica com decifração distribuída")
    p.add_argument("--sem-autoridade", type=int, nargs="+", metavar="N",
                   help="[ataque] omite a(s) autoridade(s) N da apuração")
    p.set_defaults(fn=cmd_apurar)

    p = sub.add_parser("demo", help="roda o roteiro completo da apresentação")
    p.add_argument("--pausa", action="store_true", help="espera Enter entre os passos")
    p.set_defaults(fn=cmd_demo)

    return parser


def main(argv=None) -> int:
    args = montar_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
