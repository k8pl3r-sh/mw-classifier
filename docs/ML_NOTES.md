# Notions ML du projet — note de synthèse

Mémo des concepts d'apprentissage automatique utilisés dans mw-classifier,
orientés « comment ça marche » et reliés au code.

## 0. Vocabulaire qui prête à confusion

- **RI** = **Réponse à Incident** (cas d'usage métier, pas de l'ML). « Attribution
  RI » = rattacher un échantillon inconnu à une famille connue en investigation.
- **ARI** = **Adjusted Rand Index** (métrique d'évaluation de clustering, cf. §9).
- **IAT** = Import Address Table (feature), **PE/ELF/Mach-O** = formats de binaires.

## 1. Le problème

Deux tâches distinctes, à ne pas confondre :

- **Clustering** (non supervisé) : regrouper N échantillons en familles **sans**
  connaître les familles à l'avance. → `models/model_kmean*.py`, `model_dbscan.py`…
- **Attribution / classification** (k-NN) : étant donné **un** nouvel échantillon,
  trouver la famille connue la plus proche. → `engine/classifier.py`.

Dans les deux cas, tout repose sur une notion de **similarité entre binaires**.

## 2. Représentation : du binaire aux « features »

On ne compare pas les octets bruts. On extrait des **tokens** (chaînes, fonctions
importées, hash de fonctions du call graph…) → chaque binaire devient un
**ensemble (set) de tokens**. Comparer deux binaires = comparer deux ensembles.

> Choix clé du projet : **une seule représentation**, le set de tokens, consommée
> ensuite par un MinHash (pas d'empilement de transformations).

## 3. Indice de Jaccard — similarité d'ensembles

Pour deux ensembles A et B :

```
J(A, B) = |A ∩ B| / |A ∪ B|     ∈ [0, 1]
```

1.0 = ensembles identiques, 0 = aucun token commun. C'est la mesure de base de
tout le projet. Problème : calculer l'intersection exacte sur des millions de
tokens et toutes les paires coûte cher → MinHash.

## 4. MinHash — estimer Jaccard vite

Idée : résumer chaque ensemble par une **signature** de taille fixe (128 valeurs
ici) telle que la **fraction de valeurs égales entre deux signatures ≈ J(A,B)**.

Mécanisme : on applique 128 fonctions de hachage ; pour chaque fonction on garde
le **minimum** sur tous les tokens de l'ensemble. Propriété : la probabilité que
deux ensembles aient le même minimum pour une fonction donnée = exactement
J(A,B). Donc comparer 128 nombres suffit à estimer Jaccard, quel que soit le
nombre de tokens. → bibliothèque `datasketch`, `minhash.jaccard()`.

Compromis : plus de permutations (num_perm) = estimation plus précise mais plus
coûteuse. 128 est un bon équilibre.

## 5. LSH — trouver les voisins sans tout comparer

Comparer toutes les paires = O(N²). **LSH (Locality-Sensitive Hashing)** découpe
les signatures MinHash en **bandes** ; deux signatures qui tombent dans la même
« case » pour au moins une bande deviennent des **candidats**. On ne calcule le
Jaccard que sur ces candidats. → `MinHashLSH`.

- Avantage : quasi-linéaire.
- Piège : le **seuil** règle le nombre de bandes ; trop haut ⇒ peu de candidats
  (rappel faible, on rate des paires proches). Dans le code, ce seuil sert aussi
  à décider la création d'une arête — cf. `docs/LIMITATIONS.md`.

## 6. Feature hashing (hashing trick)

Transformer un ensemble de tokens (texte) en **vecteur numérique de taille fixe**
en hachant chaque token vers un indice. Permet aux algos qui veulent des vecteurs
(KMeans…) de manger du texte. Risque : **collisions** (deux tokens → même case).
Non utilisé actuellement (c'est le levier d'amélioration du clustering).

## 7. Supervisé vs non supervisé

- **Non supervisé** : pas de labels pendant l'apprentissage (clustering). On
  *découvre* la structure.
- **Supervisé** : on apprend à partir d'exemples étiquetés. Ici le k-NN est un
  « supervisé paresseux » : pas d'entraînement, on compare directement aux
  exemples connus.

## 8. Les algorithmes de clustering

Tous travaillent sur une **matrice** (lignes = échantillons, colonnes = features)
et une **distance** (ici distance de Jaccard = 1 − J).

- **K-Means** : partitionne en **k** groupes autour de **centroïdes**. Simple et
  rapide, mais : il faut **fixer k**, il force tout le monde dans un groupe (pas
  de bruit), et il suppose des groupes « sphériques » (mal adapté au binaire).
- **K-Means non supervisé (silhouette)** : on essaie plusieurs k et on garde
  celui qui maximise le **score de silhouette** (à quel point les points sont
  proches de leur groupe vs du voisin). Attention : la plage de k doit couvrir le
  vrai nombre de familles.
- **Agglomératif (hiérarchique)** : part de N singletons et **fusionne** les plus
  proches par étapes (linkage = règle de fusion). Donne une hiérarchie ; nécessite
  une matrice de distances O(N²).
- **DBSCAN** : regroupe par **densité** (eps = rayon, min_samples = voisins requis).
  Pas besoin de k, et **étiquette les isolés en bruit (-1)** → utile pour « famille
  inconnue ». Mais très sensible à `eps`.
- **HDBSCAN** : version hiérarchique de DBSCAN, gère des **densités variables**
  sans régler `eps` ; garde la notion de bruit.

## 9. Évaluer : a-t-on raison ?

**Vérité terrain (ground truth)** : ici la famille réelle = préfixe du nom de
fichier APT1. Sans elle, impossible de mesurer.

### Attribution (k-NN) — `evaluation/classifier_eval.py`
- **Leave-one-out (LOO)** : on retire un échantillon, on le classe avec les
  autres, on vérifie `prédite == vraie`. Évite la **fuite de données** (se
  retrouver soi-même). L'**accuracy** = % de bonnes attributions.
- **Matrice de confusion** : qui est confondu avec qui (révèle le code partagé
  réel, ex. BISCUIT↔BANGAT).
- **Singletons** : une famille à 1 seul membre est irrécupérable en LOO → on
  reporte aussi l'accuracy hors singletons.

### Clustering — `evaluation/clustering_eval.py`
Comparent la partition trouvée aux familles réelles :
- **ARI** (Adjusted Rand Index) : accord des paires, **corrigé du hasard**
  (0 ≈ aléatoire, 1 = parfait). La métrique de référence.
- **NMI** (Normalized Mutual Information) : information partagée entre partition
  et familles, normalisée dans [0,1].
- **Homogénéité** : un cluster ne contient-il qu'une seule famille ?
- **Complétude** : une famille est-elle rassemblée dans un seul cluster ?
- **V-measure** : moyenne harmonique des deux (comme un F1 du clustering).
- **Silhouette** : qualité **interne** (sans labels) de la séparation des clusters.

> Astuce lecture : forte **homogénéité** + faible **complétude** = on sur-découpe
> (familles éclatées) ; l'inverse = on sous-découpe (familles fusionnées).

## 10. Pièges à retenir

- **Représentation présence/absence** : réduire une feature riche à « présent ?
  oui/non » jette le signal fin (cf. `docs/LIMITATIONS.md`).
- **Fuite de données** : évaluer un modèle sur des données qu'il a « vues » gonfle
  les scores → d'où le LOO.
- **Déséquilibre / singletons** : les petites familles biaisent les moyennes.
- **Granularité des labels** : la vérité terrain peut être plus fine que les
  familles de *code* ; une « erreur » peut être une vraie proximité de code.
- **Approximation** : MinHash et LSH sont **approximés** (variance, rappel < 1) ;
  un ré-ranking Jaccard exact sur les candidats corrige le classement final.
