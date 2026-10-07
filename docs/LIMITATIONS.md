# Limites connues — modèles & features

Document de référence sur les limites de chaque modèle de similarité et des
features d'extraction. À tenir à jour quand le comportement change.

> **Limite transverse la plus importante.** Les modèles de *clustering*
> (`KMeans_Model`, `KMeans_Model_Unsupervised`, `Agglomerative_Model`,
> `DBSCAN_Model`, `HDBSCAN_Model`) travaillent sur une matrice binaire de
> **présence/absence des clés de feature** (`clustering_utils.build_feature_matrix`,
> `X[i,j] = 1 if attrs.get(feat) else 0`). Pour une feature qui n'expose qu'une
> seule clé (`strings`, `call_graph`, `imphash`, `pe_sections`, `rich_header`,
> `pe_resources`), **tout le contenu riche est réduit à un seul bit** « présent /
> absent ». Seuls `static_iat` (une clé par DLL) apporte plusieurs colonnes.
> Conséquence : le signal fin (code partagé du call graph, chaînes communes…)
> n'est **pas** exploité par le clustering — seuls `LSH_Model` et le `Classifier`
> l'utilisent via le MinHash par token. C'est le principal plafond de qualité du
> clustering, à lever en construisant la matrice à partir des tokens hashés.

---

## Modèles

### LSH_Model
- Similarité = Jaccard MinHash approximé (`num_perm=128`) → variance d'estimation.
- Le `threshold` sert **à la fois** au banding LSH et au seuil de création
  d'arête : un seuil trop élevé réduit les bandes (b < 2 → modèle inopérant) et
  fait manquer des paires.
- Ne compare que les paires candidates renvoyées par LSH (rappel < 1) : des
  paires réellement proches mais non bucketisées sont ignorées.
- Set-based pur : aucun poids par importance/fréquence de token ; un échantillon
  au très grand ensemble de tokens peut dominer.

### KMeans_Model (k fixé)
- Représentation présence/absence grossière (cf. limite transverse).
- `n_clusters` doit être connu d'avance.
- KMeans euclidien sur données binaires est mal adapté (pas de métrique Jaccard).
- Tous les échantillons sont forcés dans un cluster (pas de notion de bruit /
  famille inconnue).
- Résultat dépendant de `random_state`.

### KMeans_Model_Unsupervised
- Mêmes limites de représentation que KMeans.
- Recherche de `k` par silhouette = `O(k)` ré-entraînements (lent) et la
  silhouette est peu fiable sur binaire/euclidien.
- Force aussi tous les échantillons dans un cluster.

### Agglomerative_Model
- Distance Jaccard **pré-calculée** mais toujours sur la matrice présence/absence
  grossière.
- Matrice de distances `O(n²)` en mémoire → ne passe pas à l'échelle sur de gros
  corpus.
- `n_clusters` requis ; linkage `average` arbitraire (choix à justifier).

### DBSCAN_Model
- Pas de `n_clusters` et gestion du bruit (`-1`) = atout pour « famille inconnue ».
- Mais `eps` très difficile à régler sur du binaire creux : résultat extrêmement
  sensible à `dbscan_eps` / `dbscan_min_samples` (tout en un cluster ou tout en
  bruit).
- Représentation grossière (cf. limite transverse).

### HDBSCAN_Model
- Nécessite scikit-learn ≥ 1.3 (import paresseux : sinon le modèle se saute).
- Gère la densité variable mieux que DBSCAN, mais reste limité par la
  représentation grossière.
- Sensible à `hdbscan_min_cluster_size` ; `O(n²)` sur distance pré-calculée.

### Classifier (k-NN, attribution d'un échantillon)
- **Utilise le MinHash par token** (contenu fin), contrairement au clustering.
- Chemin HNSW activé seulement au-delà de `BRUTE_FORCE_MAX = 5000` échantillons :
  peu testé à petite échelle, et la recall L2-sur-hashvalues est approximée
  (atténuée par sur-échantillonnage + re-ranking Jaccard exact).
- Le vote de famille pondéré par Jaccard peut être biaisé par de nombreux voisins
  faibles.
- La « confiance » = part de vote, **pas** une probabilité calibrée.
- Un échantillon déjà présent dans le corpus matche contre lui-même (score 1.0).

---

## Features

### call_graph (capstone)
- **Sweep linéaire**, pas de reconstruction de CFG : sur binaire packé ou avec
  beaucoup de données inline, le désassemblage dérive → fonctions bruitées.
  Sur de l'empaqueté, prévoir un désassembleur récursif (angr / radare2).
- Hash de fonction basé sur les **mnémoniques seuls** : robuste aux adresses/
  relocations, mais collisions possibles entre fonctions au même squelette.
- Appels **indirects** (`call eax`, `call [mem]`) ignorés → arêtes manquantes.
- Dépend de capstone/pefile (import paresseux : renvoie `{}` si absent).
- Cap à `MAX_INSTRUCTIONS = 300000` : tronque les très gros binaires.
- Signal riche **non exploité par le clustering** (cf. limite transverse).

### static_iat
- PE : imports groupés par DLL (une clé par DLL). ELF/Mach-O : API abstraite LIEF
  (une clé `imported_functions` + `libraries`) → granularité différente entre
  formats.
- Les binaires sans table d'import (statiques, packés) ne produisent rien.

### strings
- Dépend du binaire Unix `strings` (`os.popen`) : non portable Windows natif
  (OK sous WSL), lent (un `fork` par fichier), fragile aux noms de fichiers.
- ASCII uniquement via `strings` par défaut (UTF-16LE partiellement manqué).

### imphash / rich_header
- PE uniquement (pefile). Renvoient `{}` pour ELF/Mach-O ou PE sans import/rich.
- imphash est un signal « tout ou rien » : identique = fort indice de même
  toolchain, mais une seule DLL modifiée change le hash.

### pe_sections / pe_resources
- Via LIEF, dépendent de la version de l'API (`entropy`, `resources_manager`) :
  en cas d'écart, l'extracteur loggue en debug et renvoie `{}`.
- Numériques (entropie, taille) **bucketisés** en tokens → perte de finesse
  volontaire pour rester compatible Jaccard.
