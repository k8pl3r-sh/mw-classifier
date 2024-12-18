#!/usr/bin/python3

import argparse
import os
import mmh3  # Updated import
import shelve
import sys
from numpy import array

NUM_MINHASHES = 256
NUM_SKETCHES = 8


def wipe_database():
    """
    This problem uses the python standard library 'shelve' database to persist
    information, storing the database in the file 'samples.db' in the same
    directory as the actual Python script.  'wipe_database' deletes this file
    effectively reseting the system.
    """
    dbpath = os.path.join(os.path.dirname(__file__), 'samples.db')
    os.system("rm -f {0}".format(dbpath))


def get_database():
    """
    Helper function to retrieve the 'shelve' database, which is a simple
    key value store.
    """
    dbpath = os.path.join(os.path.dirname(__file__), 'samples.db')
    return shelve.open(dbpath, protocol=2, writeback=True)


def getstrings(fullpath):
    """
    Extract strings from the binary indicated by the 'fullpath'
    parameter, and then return the set of unique strings in
    the binary.
    """
    strings = os.popen("strings '{0}'".format(fullpath)).read()
    strings = set(strings.split("\n"))
    return strings


def pecheck(fullpath):
    """
    Check if a file is a PE (Portable Executable) by reading the first two bytes.
    """
    try:
        with open(fullpath, 'rb') as f:
            return f.read(2) == b'MZ'  # Read as binary and compare to binary 'MZ'
    except IOError:
        return False


def minhash(attributes):
    """
    This is where the minhash magic happens, computing both the minhashes of
    a sample's attributes and the sketches of those minhashes.  The number of
    minhashes and sketches computed is controlled by the NUM_MINHASHES and
    NUM_SKETCHES global variables declared at the top of the script.
    """
    minhashes = []
    sketches = []
    for i in range(NUM_MINHASHES):
        minhashes.append(
            min([mmh3.hash(attribute, i) for attribute in attributes])
        )
    for i in range(0, NUM_MINHASHES, NUM_SKETCHES):
        sketch = mmh3.hash(''.join(map(str, minhashes[i:i+NUM_SKETCHES])))
        sketches.append(sketch)
    return array(minhashes), sketches


def store_sample(path):
    """
    Function that stores a sample and its minhashes and sketches in the
    'shelve' database
    """
    db = get_database()
    attributes = getstrings(path)
    minhashes, sketches = minhash(attributes)

    for sketch in sketches:
        sketch = str(sketch)
        if sketch not in db:
            db[sketch] = set([path])
        else:
            obj = db[sketch]
            obj.add(path)
            db[sketch] = obj
        db[path] = {'minhashes': minhashes, 'comments': []}
        db.sync()

    print(f"Extracted {len(attributes)} attributes from {path} ...")


def comment_sample(path):
    """
    Function that allows a user to comment on a sample.  The comment the
    user provides shows up whenever this sample is seen in a list of similar
    samples to some new samples, allowing the user to reuse her or his
    knowledge about their malware database.
    """
    db = get_database()
    comment = input("Enter your comment:")
    if path not in db:
        store_sample(path)
    comments = db[path]['comments']
    comments.append(comment)
    db[path]['comments'] = comments
    db.sync()
    print("Stored comment:", comment)


def search_sample(path):
    """
    Function searches for samples similar to the sample provided by the
    'path' argument, listing their comments, filenames, and similarity values
    """
    db = get_database()
    attributes = getstrings(path)
    minhashes, sketches = minhash(attributes)
    neighbors = []

    for sketch in sketches:
        sketch = str(sketch)

        if sketch not in db:
            continue

        for neighbor_path in db[sketch]:
            neighbor_minhashes = db[neighbor_path]['minhashes']
            similarity = (neighbor_minhashes == minhashes).sum() / float(NUM_MINHASHES)
            neighbors.append((neighbor_path, similarity))

    neighbors = list(set(neighbors))
    neighbors.sort(key=lambda entry: entry[1], reverse=True)
    print("")
    print("Sample name".ljust(64), "Shared minhash estimate")
    for neighbor, similarity in neighbors:
        short_neighbor = neighbor.split("/")[-1]
        comments = db[neighbor]['comments']
        print(str("[*] " + short_neighbor).ljust(64), similarity)
        for comment in comments:
            print("\t[comment]", comment)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="""
Simple sharing search system which allows you to build up a database of malware samples (indexed by file paths) and
then search for similar samples given some new sample
"""
    )

    parser.add_argument(
        "-l", "--load", dest="load", default=None,
        help="Path to directory containing malware, or individual malware file, to store in database"
    )

    parser.add_argument(
        "-s", "--search", dest="search", default=None,
        help="Individual malware file to perform similarity search on"
    )

    parser.add_argument(
        "-c", "--comment", dest="comment", default=None,
        help="Comment on a malware sample path"
    )

    parser.add_argument(
        "-w", "--wipe", action="store_true", default=False,
        help="Wipe sample database"
    )

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
    if args.load:
        malware_paths = []  # where we'll store the malware file paths
        malware_attributes = dict()  # where we'll store the malware strings

        for root, dirs, paths in os.walk(args.load):
            # walk the target directory tree and store all the file paths
            for path in paths:
                full_path = os.path.join(root, path)
                malware_paths.append(full_path)

        # filter out any paths that aren't PE files
        malware_paths = list(filter(pecheck, malware_paths))

        # get and store the strings for all the malware PE files
        for path in malware_paths:
            store_sample(path)

    if args.search:
        search_sample(args.search)

    if args.comment:
        comment_sample(args.comment)

    if args.wipe:
        wipe_database()
