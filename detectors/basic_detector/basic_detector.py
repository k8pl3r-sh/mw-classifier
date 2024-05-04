import os
import sys
import pickle
import argparse
import re
import pefile
import numpy
from sklearn.feature_extraction import FeatureHasher

def get_string_features(path: str, hasher: FeatureHasher):
    MIN_LENGTH = 5

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

def scan_file(path: str):
    # scan a file to determine if it is malicious or benign
    if not os.path.exists("saved_detector.pkl"):
        print("It appears you haven't trained a detector yet!  Do this before scanning files.")
        sys.exit(1)
    with open("saved_detector.pkl", "rb") as saved_detector:
        classifier, hasher = pickle.load(saved_detector)
    features = get_string_features(path,hasher)
    result_proba = classifier.predict_proba([features])[:,1]

    # if the user specifies malware_paths and benignware_paths, train a detector
    is_malware = result_proba[0] > 0.5
    filename = os.path.basename(path)
    result = f"{filename},{bool(is_malware)},{result_proba[0]}"
    # str tricks is because it returns [ True] or [False] and we want true or false
    return result

def scan_directory(path: str, output_file: str):
    file_paths = []
    results = {}
    # Walk through the directory and its subdirectories
    for root, _, files in os.walk(path):
        for file in files:
            # Get the full path of each file and append it to the list
            file_paths.append(os.path.join(root, file))


    if output_file:
        with open(output_file, "w") as outfile:
            for element in file_paths:
                result = scan_file(element)
                outfile.write(result + '\n')
    else:
        for element in file_paths:
            result = scan_file(element)
            print(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser("get windows object vectors for files")
    # parser.add_argument("--scan_file_path", default=None, help="File to scan")
    parser.add_argument("--scan_dir_path", default=None, help="Directory to scan")
    parser.add_argument("--output", default=None, help="File to output results to")


    args = parser.parse_args()

    hasher = FeatureHasher(20000)

    # if args.scan_file_path:
    #    scan_file(args.scan_file_path)
    if args.scan_dir_path:
        scan_directory(args.scan_dir_path, args.output)
    else:
        print("[*] You did not specify a path to scan," \
            " please specify one of these to use the detector.\n")
        parser.print_help()