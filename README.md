# MW-Classifier

This project is a studnet project of a Malware-Classifier.
 Machine Learning research on malware detection and attribution

All the work is based on the amazing book **Malware Data Science** !

## Project architecture
The project's global architecture is as follow :

```
mw-classifier/
│
├── main.py                                    # Main application entry point
├── config.yml                                 # Config parameters
├── cached_features.pkl                        # Cached python malware features with Pickle for fast debugging
├── features/                                  # Contains all features extractors for malware samples
│   ├── features_extractor.py                  # Simultaneous localization
│   ├── strings.py                             # Simultaneous localization
│   └── static_iat.py                          # Template class for a module object
├── SAMPLES/                                   # Contains malware samples for testing and debugging
├── graphics/                                  # Contains all chart results to evaluate the model (similarity matrix...)
├── engine/                                    # Heart of the project, orchestrate features extractor, database or caching and execution of a model
│   ├── similarity_engine.py                   # Orchestrator of the project execution
│   ├── minhashcustom.py                       # Simultaneous localization
│   └── redis_storage.py                       # Template class for a module object
├── models/                                    # Contains all similarity analysis models
│   ├── model_template.py                      # Simultaneous localization
│   ├── model_runner.py                        # Simultaneous localization
│   └── hnsw_search_nearest_neighbor.py        # Template class for a module object
├── utils/                                     # Useful functions like Logger, Config class, Neo4J utilities
│   ├── config.py                              # Config class to avoid passing config as parameter for each class object
│   ├── logger.py                              # Logging class
│   ├── neo4j_graph.py                         # Neo4J class to manage graph objects
│   └── tools.py                               # Standalone functions (load YAML file...)
├── tests/                                     # Unit tests for the application to be implemented
└── requirements.txt                           # Project dependencies

```

## Installation

1) `sudo apt install build-essential libsystemd-dev` in order to install systemd python lib (or you will get `ERROR: Failed building wheel for cysystemd`)

2) Clone the repository : `git clone`

3) Rename `config.sample.py` to `config.py` and fill the fields with your own values.
To avoid any issue risking a detonation, makes the `SAMPLES` folder in read only mode.

4) Set up venv and install requirements :
```bash
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

5) In order to run the complete project with databases, start docker containers with `docker-compose up -d` and then run the project.
It is not necessary for Neo4J docker which is started via Docker Python API inside the code.
It is useful only if you use Redis and so on !
The compose file is built in a way that you can chose which services are launched like `docker compose up -d redis` to start the redis server database.

Run : `docker compose up -d neo4j` (by default) then `python3 main.py`

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

**Jaccard index**


## Similarity Engine

Based on a dataset (here APT1), makes graph of similarity between malware samples which can be associated as families.

Start it with `python3 main.py`, the Neo4J docker is started with Python code !

