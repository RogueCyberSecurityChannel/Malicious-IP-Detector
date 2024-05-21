import subprocess
import requests
#  from requests.exceptions import ConnectionError, RequestException
import time
import sys

def web_scrape_and_process(url):
    response = requests.get(url)

    if response.status_code == 200:
        raw_data = response.text
    return raw_data

def banned_ip_parser(data):
    ip_list = data.splitlines()
    banned_ips =  [line.split() [0] for line in ip_list if line.strip()]
    return banned_ips[7:]

def netstat(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        output_lines = result.stdout.splitlines()
        foreign_ips = [line.split()[2] for line in output_lines if len(line.split()) == 4]
        for ip in foreign_ips:
            if ip == "0.0.0.0:0":
                foreign_ips.remove(ip)
        return foreign_ips
    except subprocess.CalledProcessError:
        pass

def find_matches(driver_list_1, driver_list_2):
    set1 = set(driver_list_1)
    set2 = set(driver_list_2)
    matches = list(set1.intersection(set2))
    return matches

def main():
    data = web_scrape_and_process('https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt')
    parsed_list = banned_ip_parser(data)

    foreign_ips = netstat('netstat -an')

    matches = find_matches(parsed_list, foreign_ips)

    match_list = []
    if len(matches):
        for match in matches:
            print(f"[!] {match}")
            match_list.append(match)
    else:
        print("[+]")
if __name__ == "__main__":
    main()
