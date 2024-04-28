import os
import requests
from bs4 import BeautifulSoup
import re
import zipfile

# TODO : check by date instead of the latest to confirm it works
# TODO : faire des fonctions
# TODO : sécuriser le dossier temp avec des droits de lecture uniquement + dans une VM/VPS, via cronjob/...
#  pour dockeriser

# URL of the page
url = "https://datalake.abuse.ch/malware-bazaar/hourly/"

# Send a GET request to the URL
response = requests.get(url)

# Check if the request was successful
if response.status_code == 200:
    # Parse the HTML content
    soup = BeautifulSoup(response.content, "html.parser")

    # Find all links to zip files
    links = soup.find_all("a", href=re.compile(r'\.zip$'))

    # Extract the link of the latest zip file
    latest_zip = links[-1]['href']  # Assuming the last link is the latest

    # Construct the full URL of the latest zip file
    full_url = url + latest_zip

    # Download the zip file
    r = requests.get(full_url)

    # Save the zip file
    with open(latest_zip, 'wb') as f:
        f.write(r.content)

    print(f"Latest zip file downloaded: {latest_zip}")

    # Create a directory to extract the contents
    directory = "temp"
    os.makedirs(directory, exist_ok=True)

    # Extract the contents of the zip file with the password "infected"
    with zipfile.ZipFile(latest_zip, 'r') as zip_ref:
        zip_ref.extractall(directory, pwd=b"infected")

    print("Zip file extracted successfully.")
else:
    print("Failed to fetch data.")
