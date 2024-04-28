#!/usr/bin/python

import os
import sys
import pickle
import argparse
import re
import pefile
import numpy
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import FeatureHasher

def get_string_features(path,hasher):
    MIN_LENGTH = 5

    # Regular expression pattern to match strings of 5 or more characters
    # string_pattern = r'\b\w{5,}\b'
    strings = []

    with open(path, 'rb') as file:
        data = file.read()

    # Regular expression pattern to match strings of 5 or more characters
    string_pattern = r'\b\w{5,}\b'

    # Find all strings matching the pattern
    matches = re.findall(string_pattern, data.decode('utf-8', errors='ignore'))

    # Filter out strings with less than 5 characters
    strings = [match for match in matches if len(match) >= 5]

    # store string features in dictionary form
    string_features = {}
    for string in strings:
        string_features[string] = 1

    # hash the features using the hashing trick
    hashed_features = hasher.transform([string_features])

    # do some data munging to get the feature array
    hashed_features = hashed_features.todense()
    hashed_features = numpy.asarray(hashed_features)
    hashed_features = hashed_features[0]

    # return hashed string features
    print("Extracted {0} strings from {1}".format(len(string_features), path))
    return hashed_features
    """
    # extract strings from binary file using regular expressions
    chars = r" -~"
    min_length = 5
    string_regexp = '[%s]{%d,}' % (chars, min_length)
    file_object = open(path)
    data = file_object.read()
    pattern = re.compile(string_regexp)
    strings = pattern.findall(data)
    """



def scan_file(path):
    # scan a file to determine if it is malicious or benign
    if not os.path.exists("saved_detector.pkl"):
        print("It appears you haven't trained a detector yet!  Do this before scanning files.")
        sys.exit(1)
    with open("saved_detector.pkl") as saved_detector:
        classifier, hasher = pickle.load(saved_detector)
    features = get_string_features(path,hasher)
    result_proba = classifier.predict_proba([features])[:,1]
    # if the user specifies malware_paths and benignware_paths, train a detector
    if result_proba > 0.5:
        print("It appears this file is malicious!", result_proba)
    else:
        print("It appears this file is benign.", result_proba)

def train_detector(benign_path,malicious_path,hasher):
    # train the detector on the specified training data
    def get_training_paths(directory):
        targets = []
        for path in os.listdir(directory):
            targets.append(os.path.join(directory,path))
        return targets
    malicious_paths = get_training_paths(malicious_path)
    benign_paths = get_training_paths(benign_path)
    X = [get_string_features(path,hasher) for path in malicious_paths + benign_paths]
    y = [1 for i in range(len(malicious_paths))] + [0 for i in range(len(benign_paths))]
    classifier = RandomForestClassifier(64)
    classifier.fit(X,y)
    pickle.dump((classifier,hasher),open("saved_detector.pkl","wb+"))

def cv_evaluate(X,y,hasher):
    # use cross-validation to evaluate our model
    import random
    from sklearn import metrics
    from matplotlib import pyplot
    from sklearn.model_selection import KFold
    X, y = numpy.array(X), numpy.array(y)
    fold_counter = 0

    kf = KFold(2, shuffle=True)
    for train, test in kf.split(X):
        training_X, training_y = X[train], y[train]
        test_X, test_y = X[test], y[test]
        classifier = RandomForestClassifier(64)
        classifier.fit(training_X,training_y)
        scores = classifier.predict_proba(test_X)[:,-1]
        fpr, tpr, thresholds = metrics.roc_curve(test_y, scores)
        #pyplot.semilogx(fpr,tpr,label="Fold number {0}".format(fold_counter))
        pyplot.semilogx(fpr,tpr,label="ROC curve".format(fold_counter))
        fold_counter += 1
        break

    # Curve representing random predictions
    # TODO : courbe x = y : random classifier
    # TODO : point x = 0, y = 1 perfect classifier
    # TODO : better classifier au dessus y=x, worse en dessous

    # TODO : calcul AUC (Area Under Curve):  probabilité que parmi 2 pers au  hasard, un malade et un non-malade
    #   la valeur du marqueur soit plus élevée pour le malade que pour le non-malade
    #   Plus c'est proche de 1 mieux c'est

    pyplot.xlabel("detector false positive rate")
    pyplot.ylabel("detector true positive rate")
    pyplot.title("Detector ROC curve")
    #pyplot.title("detector cross-validation ROC curves")
    pyplot.legend()
    pyplot.grid()
    pyplot.show()

def get_training_data(benign_path,malicious_path,hasher):
    def get_training_paths(directory):
        targets = []
        for path in os.listdir(directory):
            targets.append(os.path.join(directory,path))
        return targets
    malicious_paths = get_training_paths(malicious_path)
    benign_paths = get_training_paths(benign_path)
    X = [get_string_features(path,hasher) for path in malicious_paths + benign_paths]
    y = [1 for i in range(len(malicious_paths))] + [0 for i in range(len(benign_paths))]
    return X, y

parser = argparse.ArgumentParser("get windows object vectors for files")
parser.add_argument("--malware_paths",default=None,help="Path to malware training files")
parser.add_argument("--benignware_paths",default=None,help="Path to benignware training files")
parser.add_argument("--scan_file_path",default=None,help="File to scan")
parser.add_argument("--evaluate",default=False,action="store_true",help="Perform cross-validation")

args = parser.parse_args()

hasher = FeatureHasher(20000)
if args.malware_paths and args.benignware_paths and not args.evaluate:
    train_detector(args.benignware_paths,args.malware_paths,hasher)
elif args.scan_file_path:
    scan_file(args.scan_file_path)
elif args.malware_paths and args.benignware_paths and args.evaluate:
    X, y = get_training_data(args.benignware_paths,args.malware_paths,hasher)
    cv_evaluate(X,y,hasher)
else:
    print("[*] You did not specify a path to scan," \
        " nor did you specify paths to malicious and benign training files" \
        " please specify one of these to use the detector.\n")
    parser.print_help()
