import requests
from re import findall
from json import loads
from termcolor import colored
from configparser import RawConfigParser


def init(domain):
    ZOOM = []

    print(colored("[*]-Searching ZoomEye...", "yellow"))

    parser = RawConfigParser()
    parser.read("config.ini")
    ZOOMEYE_API_KEY = parser.get("ZoomEye", "ZOOMEYE_API_KEY")

    if not ZOOMEYE_API_KEY:
        print("  \__", colored("No ZoomEye API key configured", "red"))
        return []

    url = f"https://api.zoomeye.org/domain/search?q={domain}&type=1&page=1"
    headers = {"API-KEY": ZOOMEYE_API_KEY, "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = loads(response.text)
            for result in data.get("list", []):
                ZOOM.append(result['name'])
        else:
            print("  \__", colored(f"Error: {response.status_code}", "red"))
    except Exception as e:
        print("  \__", colored(f"Error: {str(e)}", "red"))

    return list(set(ZOOM))