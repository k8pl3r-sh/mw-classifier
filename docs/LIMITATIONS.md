# Limites connues — modèles & features

Document de référence sur les limites de chaque modèle de similarité et des
features d'extraction. À tenir à jour quand le comportement change.

> **Représentation du clustering (résolu, nouveau compromis).** Les modèles de
> *clustering* (`KMeans_Model`, `KMeans_Model_Unsupervised`, `Agglomerative_Model`,
> `DBSCAN_Model`, `HDBSCAN_Model`) utilisaient à l'origine une matrice binaire de
> **présence/absence des clés de feature** (tout le contenu riche réduit à 1 bit).
> C'est désormais corrigé : `clustering_utils.build_feature_matrix` applique le
> **hashing trick** — chaque token (préfixé par sa feature, comme le MinHash) est
> haché vers une colonne parmi `clustering.hash_dim` (défaut 16384), incidence
> binaire. Le contenu (strings, call graph, imports…) est donc exploité par le
> clustering. **Nouveau compromis** : les **collisions de hachage** (deux tokens →
> même colonne) ; augmenter `hash_dim` les réduit au prix de la mémoire. Les
> features très verbeuses (`strings`, `call_graph`) peuvent saturer les colonnes
> et rapprocher artificiellement les échantillons si `hash_dim` est trop petit.

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
- Matrice tokens hachés (cf. note représentation) : sensible aux collisions.
- `n_clusters` doit être connu d'avance.
- KMeans euclidien sur données binaires est mal adapté (pas de métrique Jaccard).
- Tous les échantillons sont forcés dans un cluster (pas de notion de bruit /
  famille inconnue).
- Résultat dépendant de `random_state`.

### KMeans_Model_Unsupervised
- Même matrice de tokens hachés que KMeans.
- Recherche de `k` par silhouette = `O(k)` ré-entraînements (lent) et la
  silhouette est peu fiable sur binaire/euclidien.
- Force aussi tous les échantillons dans un cluster.

### Agglomerative_Model
- Distance Jaccard **pré-calculée** sur la matrice de tokens hachés.
- Matrice de distances `O(n²)` en mémoire → ne passe pas à l'échelle sur de gros
  corpus.
- `n_clusters` requis ; linkage `average` arbitraire (choix à justifier).

### DBSCAN_Model
- Pas de `n_clusters` et gestion du bruit (`-1`) = atout pour « famille inconnue ».
- Mais `eps` très difficile à régler sur du binaire creux : résultat extrêmement
  sensible à `dbscan_eps` / `dbscan_min_samples` (tout en un cluster ou tout en
  bruit).

### HDBSCAN_Model
- Nécessite scikit-learn ≥ 1.3 (import paresseux : sinon le modèle se saute).
- Gère la densité variable mieux que DBSCAN.
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
