# ml-malware
 Machine Learning research on malware detection and attribution


## Similarity Engine

Based on a dataset (here APT1), makes graph of similarity between malware samples which can be associated as families.

Start it with `python3 main.py`

## Malware detector

Train a model on a dataset (here APT1), by extracting features from samples and apply the classifier on it

## Network-ml

Makes a graph from a pcap file to create a graph of the network traffic

Start it with `python3 network-ml/network_graph.py`