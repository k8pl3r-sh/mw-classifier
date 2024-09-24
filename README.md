# ml-malware
 Machine Learning research on malware detection and attribution

All the work is based on the amazing book [Malware Data Science](Malware.pdf) !



## Installation

`sudo apt install libsystemd-dev` pour install systemd
-> installation des requirements

Clone the repository : `git clone`
Rename `config.sample.py` to `config.py` and fill the fields with your own values.

To avoid any issue risking a detonation, makes the `SAMPLES` folder in read only mode.

Create VENV : `python3 -m venv venv`
Enable VENV : `source venv/bin/activate`
Install requirements : `pip install -r requirements.txt`

Run : `python3 main.py`

#### Datasets

- Famille APT 1 (Mandiant)
- Benignware / Malware
- VX-Underground database
- Ransomware notes : 
use `find . -type f -exec bash -c 'mv "$0" "$(dirname "$0")/X$(basename "$0")"' {} \;` to add `X_` at the start of every filenames to avoid neo4j syntax errors

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

Start it with `python3 main.py`, the Neo4J docker is started with Python code !

## Malware detector

Train a model on a dataset (here APT1), by extracting features from samples and apply the classifier on it

