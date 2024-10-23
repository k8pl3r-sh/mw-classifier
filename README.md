# ml-malware
 Machine Learning research on malware detection and attribution

All the work is based on the amazing book [Malware Data Science](Malware.pdf) !


## Installation

`sudo apt install libsystemd-dev` in order to install systemd python lib (or you will get `ERROR: Failed building wheel for cysystemd`)

Clone the repository : `git clone`
Rename `config.sample.py` to `config.py` and fill the fields with your own values.
To avoid any issue risking a detonation, makes the `SAMPLES` folder in read only mode.

Set up venv and install requirements :
```bash
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

In order to run the complete project with databases, start docker containers with `docker-compose up -d` and then run the project.
It is not necessary for Neo4J docker which is started via Docker Python API inside the code.
It is useful only if you use Redis and so on !

Run : `python3 main.py`

#### Datasets

In order to use the project, you can use this dataset for instance : https://github.com/cyber-research/APTMalware/tree/master

I personally use Mandiant APT1 dataset and VX-Underground dataset, thank you very much for your work ;)

## Project's overview


Tree :
- features : contain scripts to extract features from a sample
- malware-similarity : scripts to make a graph of similarity between malware samples
- utils : utilities functions
- shared_code_analysis : scripts to train a model on a dataset and then detect similarities with a submited sample
- 

## ML functions overview

**Jaccard index** :


## Similarity Engine

Based on a dataset (here APT1), makes graph of similarity between malware samples which can be associated as families.

Start it with `python3 main.py`, the Neo4J docker is started with Python code !
