import subprocess
import requests
from ipwhois import IPWhois
import pprint
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
        raw_ips = [line.split()[2] for line in output_lines if len(line.split()) == 5]
        raw_pids = [line.split()[4] for line in output_lines if len(line.split()) == 5]
        foreign_ips = []
        pids = []
        index2 = 0
        for ip in raw_ips:
            index2 = index2 + 1
            if "[" in ip:
                continue
            if "0.0.0.0" in ip:
                continue
            if '127.0.0.1' in ip:
                continue
            if ":" in ip:
                index = ip.find(":")
                foreign_ips.append(ip[:index])
                pids.append(raw_pids[index2 - 1])
        return foreign_ips, pids
    except subprocess.CalledProcessError:
        pass

def host_ip_parser(data):
    ips = []
    for line, slice in enumerate(data):
        for index in range(len(slice) - 1):
            if slice[index:index + 1] == ':':
                ip = data[line][:index]
                ips.append(ip)
        return ips

def find_matches(driver_list_1, driver_list_2):
    set1 = set(driver_list_1)
    set2 = set(driver_list_2)
    matches = list(set1.intersection(set2))
    return matches

def lists_to_dict(keys, values):
    return dict(zip(keys, values))

def main():
    data = web_scrape_and_process('https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt')
    parsed_ip_list = banned_ip_parser(data)

    output = netstat('netstat -ano')
    host_ips = output[0]
    host_pids = output[1]

    ip_pid_dictionary = lists_to_dict(host_ips, host_pids)

    matches = find_matches(parsed_ip_list, host_ips)
    match_list = []
    if len(matches):
        for match in matches:
            print(f"[!] ACTIVE CONNECTION TO KNOWN MALICIOUS IP DETECTED")
            match_list.append(match)
    else:
        print("[+] No active malicious ip connections detected")
    for match in match_list:
        print(f'IP: {match} PID: {ip_pid_dictionary[match]}')

if __name__ == "__main__":
    main()
