
from structure import *
import requests
import json
import argparse
import hashlib
import os
import yaml

# TODO : check les différents hashs si fichier et Not Found

def load_config(path: str) -> dict:
    with open(path, 'r') as f:
        config = yaml.safe_load(f)
    return config

def list_files_directory(directory: str, exclusion_path=None) -> list[str]:
    file_paths = []
    # TODO : try except sur l'existence du chemin
    # TODO : manage exclusion path

    # Walk through the directory and its subdirectories
    if os.path.exists(directory):
        for root, _, files in os.walk(directory):
            for file_ in files:
                file_path = os.path.join(root, file_)
                file_paths.append(file_path)
    return file_paths

class QueryVT(object):
    round_index = 0

    def __init__(self, config: dict):
        self.api_key = config['api_key']  # liste de clé
        self.response = None

    @staticmethod
    def _response_handler(response: dict) -> dict:
        # Handle the response from the API
        result = json.loads(response.text)

        if 'error' in result:
            print(f"Error: {result['error']['message']}")
            return None
        else:
            return result["data"]["attributes"]

    def query_hash(self, hash: str) -> binary:
        # Query to the API
        # Submit
        self._rotate_key()
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.key
        }
        self.url = "https://www.virustotal.com/api/v3/files/" + str(hash)
        response = requests.get(self.url, headers=self.headers)
        result = self._response_handler(response)
        if result:
            return binary(**result)

    def query_domain(self, domain_str) -> domain:
        # Query to the API
        self._rotate_key()
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.key
        }
        self.url = "https://www.virustotal.com/api/v3/domains/" + str(domain_str)
        response = requests.get(self.url, headers=self.headers)
        result = self._response_handler(response)
        if result:
            return domain(**result)

    def query_ip(self, ip_str) -> ip:
        self._rotate_key()
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.key
        }
        self.url = "https://www.virustotal.com/api/v3/ip_addresses/" + str(ip_str)
        response = requests.get(self.url, headers=self.headers)
        result = self._response_handler(response)
        if result:
            return ip(**result)

    @staticmethod
    def query_directory(list_path: list) -> list:
        list_ = []
        for element in list_path:
            #list_.append()
            pass
        return list_



    def _rotate_key(self):
        # Rotate the API key to stay under the RateLimit of the API
        self.key = self.api_key[QueryVT.round_index % len(self.api_key)]
        QueryVT.round_index += 1
        # Do not check if errors happened

    def _check_quota(self):
        # Check Rate Limit
        # TODO : find a way to check the rate limit via the API indications
        pass

    def _scan_files(self, files_path: list):
        # Scan files in a directory to submit its hashes
        pass

    def _update_db(self):
        # Update the database with the VT results
        pass

    def _set_db(self):
        # Set the database to store VT results
        pass


def cli_parser() -> dict:
    parser = argparse.ArgumentParser(description="VT-Fast : A fast and efficient VirusTotal CLI tool.")

    # Add command-line arguments
    parser.add_argument('-hash', dest='hash_value', nargs='+', metavar='HASH', help='Specify the hash value')
    parser.add_argument('-i', dest='ip_address', metavar='IP', help='Specify the IP address')
    parser.add_argument('-f', dest='file_path', metavar='FILE', help='Specify the file path')
    parser.add_argument('-d', dest='domain', metavar='DOMAIN', help='Specify domain to search')
    parser.add_argument('-p', dest='directory_path', metavar='PATH', help='Specify the path of a directory to hunt')
    parser.add_argument('-c', dest='config_file', metavar='config', help='Specify the path of the config file')
    parser.add_argument('-e', dest='exclude_path', metavar='exclude', help='Specify path to exclude')
    # Parse the command-line arguments
    args = parser.parse_args()


    # Handle the parsed arguments
    # TODO : à virer, juste pour du debug
    if args.hash_value:
        print(f"Hash value: {args.hash_value}")
    if args.ip_address:
        print(f"IP address: {args.ip_address}")
    if args.file_path:
        print(f"File path: {args.file_path}")
    if args.domain:
        print(f"Domain: {args.domain}")
    if args.directory_path:
        print(f"Directory path: {args.directory_path}")
    if args.config_file:
        print(f"Config file: {args.config_file}")

    return args


def pretty_results(self):
    # Pretty print the results
    # TODO : voir si gestion unitaire IP/... ou globale
    pass


def show_results(self):
    # Show the results
    pass


def hash_file(file_path: str) -> str:
    # Hash a file
    md5_hash = hashlib.md5()

    try:
        with open(file_path, 'rb') as file:
            # Read the file in chunks to avoid loading the entire file into memory
            for chunk in iter(lambda: file.read(4096), b''):
                md5_hash.update(chunk)
    except FileNotFoundError:
        return None  # Return None if the file is not found

    return md5_hash.hexdigest()


def test():
    # TODO : check argument -c config
    config = load_config('config.yml')
    vt = QueryVT(config['virustotal'])
    r = vt.query_hash('d123fb453fd6867f2a50d05fe6fd4225e9bb9f5ccb3cd143312652b3ed45dd70')
    print(r.detectiteasy)

    d = vt.query_domain('google.com')
    print(d)

    i = vt.query_ip('8.8.8.8')
    print(i.total_votes)


def main():
    args = cli_parser()
    if args.config_file:
        config = load_config(args.config_file)
    else:
        config = load_config('../../config.yml')

    vt = QueryVT(config['virustotal'])

    if args.hash_value:
        for hash in args.hash_value:
            result = vt.query_hash(hash)
            print(vt.key)
            if result:
                print(f" {hash} : {result.tags}")
    if args.directory_path:
        if args.exclude_path:
            file_list = list_files_directory(args.directory_path, args.exclude_path)

        else:
            file_list = list_files_directory(args.directory_path)
        print(file_list)

        for file in file_list:
            result = vt.query_hash(str(hash_file(file)))

            if result:
                print(f" {file} : {result.tags}")


if __name__ == '__main__':
    main()
