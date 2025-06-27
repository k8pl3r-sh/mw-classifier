import r2pipe
import networkx as nx
import pydot

def dot_to_networkx(dot_path):
    (graph,) = pydot.graph_from_dot_file(dot_path)
    G = nx.nx_pydot.from_pydot(graph)
    return G


def compare_cfgs(dot1, dot2):
    G1 = dot_to_networkx(dot1)
    G2 = dot_to_networkx(dot2)

    # Graphe non orienté pour simplifier la distance
    G1 = G1.to_undirected()
    G2 = G2.to_undirected()

    ged = nx.graph_edit_distance(G1, G2)
    print(f"Graph Edit Distance: {ged}")

"""

Mesure combien d'opérations (ajout/suppression de noeuds/arêtes) sont nécessaires pour passer d’un graphe à un autre.

NetworkX a nx.graph_edit_distance() mais c’est très lent sur les gros graphes.


Sinon passer en GRAPH EMBEDDINGS : 
Convertir chaque graphe en un vecteur de caractéristiques (par ex. counts de motifs, degré des noeuds, distribution, etc.)

Puis utiliser un score de similarité vectorielle (cosinus, Euclidien, etc.)

Cela nécessite un peu plus de travail et peut impliquer des bibliothèques de graph embedding (e.g. node2vec, graph2vec)."""


def extract_cfg(binary_path, arch="x86", bits=64, base=0x400000, output_dot="graph.dot"):
    opts = ["-a", arch, "-b", str(bits), "-m", hex(base), "-e", "bin.relocs.apply=true"]

    r2 = r2pipe.open(binary_path, flags=['-2']) #,opts
    # r2.cmd("e bin.relocs.apply=true")
    r2.cmd("aaaa")  # analyse plus poussée
    dot = r2.cmd("agfd .")  # graphe complet, souvent plus riche que agfd .
    r2.quit()

    if not dot.strip():
        print("Warning: empty DOT graph, try verifying binary and options.")
        return

    with open(output_dot, "w") as f:
        f.write(dot)
    print(f"DOT graph saved to {output_dot}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python extract_cfg.py <binary_1> <binary_2>")
        exit(1)
    extract_cfg(sys.argv[1], output_dot="bin_1.dot")
    extract_cfg(sys.argv[2], output_dot="bin_2.dot")

    compare_cfgs("bin_1.dot", "bin_2.dot")