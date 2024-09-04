# ml-malware
 Machine Learning research on malware detection and attribution

All the work is based on the amazing book [Malware Data Science](Malware.pdf) !



## Installation

`sudo apt install libsystemd-dev` pour install systemd
-> installation des requirements

To avoid any issue risking a detonation, makes the `SAMPLES` folder in read only mode.

#### Datasets

- Famille APT 1 (Mandiant)
- Benignware / Malware
- VX-Underground database

## Project's overview


Tree :
- features : contain scripts to extract features from a sample
- malware-detectors : scripts to train a model on a dataset and detect if a PE is malicious
- malware-similarity : scripts to make a graph of similarity between malware samples
- utils : utilities functions
- samples_downloader : scripts to download samples from a dataset (malwarebazaar or malwaretraffic)
  See C2-Hunter repository in order to download other samples (ThreatFox, VT..)
- shared_code_analysis : scripts to train a model on a dataset and then detect similarities with a submited sample
- 

## ML functions overview

**Jaccard index** :


## Similarity Engine

Based on a dataset (here APT1), makes graph of similarity between malware samples which can be associated as families.

Start it with `python3 main.py`

## Malware detector

Train a model on a dataset (here APT1), by extracting features from samples and apply the classifier on it

