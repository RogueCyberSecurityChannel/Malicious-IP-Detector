import subprocess
import threading
import requests
from requests.exceptions import ConnectionError, RequestException
import time
import sys
import ctypes
from datetime import datetime

def welcome():
    print(r'''
       __  ___        __ _        _                        ____ ____     ____         __               __
      /  |/  /____ _ / /(_)_____ (_)____   __  __ _____   /  _// __ \   / __ \ ___   / /_ ___   _____ / /_ ____   _____
     / /|_/ // __ `// // // ___// // __ \ / / / // ___/   / / / /_/ /  / / / // _ \ / __// _ \ / ___// __// __ \ / ___/
    / /  / // /_/ // // // /__ / // /_/ // /_/ /(__  )  _/ / / ____/  / /_/ //  __// /_ /  __// /__ / /_ / /_/ // /
   /_/  /_/ \__,_//_//_/ \___//_/ \____/ \__,_//____/  /___//_/      /_____/ \___/ \__/ \___/ \___/ \__/ \____//_/
  -------------------------------------------------------------------------------------------------------------------
                                 {GitHub:https://github.com/RogueCyberSecurityChannel}''')

def header(date, time):
    header_file = f"""
********************************************************
              Malicious-Ip-Detector Log
  [GitHub:https://github.com/RogueCyberSecurityChannel]

  Date: {date}
  Time: {time}

********************************************************"""
    return header_file

def running_animation():
    animation = "|/-\\"
    i = 0
    while True:
        sys.stdout.write( "\r" + f" ["  + animation[i % len(animation)] + "] ")
        sys.stdout.flush()
        i += 1
        time.sleep(1)

def log_to_file(message):
    with open('Malicious-IP_Detector_log.csv', 'a') as fd:
        fd.write(f'{message}\r\n')

def log_message_generator(match, raw_pid_info, path, hash):
    pid = "\n".join(line for line in raw_pid_info)
    current_datetime = datetime.now()
    time = current_datetime.strftime("%I:%M:%S %p")
    date = current_datetime.strftime('%B %d, %Y')
    log_message = (
        f'Date: {date}'
        f'\nTime: {time}'
        f'\nIP: {match}'
        f'\nFilepath: {path}'
        f'\nSHA256 Hash: {hash}'
        f'\nProcess information: {pid}\n\n'
    )
    log_to_file(log_message)

def pop_up(message):
    ctypes.windll.user32.MessageBoxW(0, message, "Malicious-IP-Detector Alert", 16)

def web_scrape_and_process(url):
    response = requests.get(url)

    if response.status_code == 200:
        raw_data = response.text
    return raw_data

def banned_ip_parser(data):
    ip_list = data.splitlines()
    banned_ips =  [line.split()[0] for line in ip_list if line.strip()]
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

def find_matches(list_1, list_2):
    set1 = set(list_1)
    set2 = set(list_2)
    matches = list(set1.intersection(set2))
    return matches

def get_timestamp():
    current_datetime = datetime.now()
    timestamp_string = current_datetime.strftime(" [*] %B %d, %Y\n [*] %I:%M:%S %p")
    return timestamp_string

def pid_info_printer(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        output_lines = result.stdout.splitlines()
        return output_lines
    except subprocess.CalledProcessError as e:
        print(f" [-] Error executing PID information command: {e}")
        sys.exit(1)

def path_finder(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        output_lines = result.stdout.splitlines()
        paths = []
        for line, slice in enumerate(output_lines):
            for index in range(len(slice) - 1):
                if slice[index:index + 2] == 'C:':
                    path = output_lines[line][index:]
                    paths.append(path)
        return paths
    except subprocess.CalledProcessError as e:
        print(f" [-] Error executing PID information command: {e}")
        sys.exit(1)

def hash_host_malware(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        output_lines = result.stdout.splitlines()
        driver_hash = output_lines[1]
        return driver_hash
    except subprocess.CalledProcessError:
        pass

def lists_to_dict(keys, values):
    return dict(zip(keys, values))


def main():
    welcome()

    current_datetime = datetime.now()
    time_for_header = current_datetime.strftime("%I:%M:%S %p")
    date = current_datetime.strftime('%B %d, %Y')
    log_header = header(date, time_for_header)
    log_to_file(log_header)
    try:
        time.sleep(1)
        data = web_scrape_and_process('https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt')
        parsed_ip_list = banned_ip_parser(data)
    except (ConnectionError, RequestException) as e:
        time.sleep(1)
        print(f' [-] An error occurred while trying to establish a secure connection. Please check your internet connection and try again later.\n')
        sys.exit(1)
    except KeyboardInterrupt:
                sys.exit(0)
    except Exception as e:
                print(str(e))
                sys.exit(1)
    while True:
            try:
                output = netstat('netstat -ano')
                host_ips = output[0]
                host_pids = output[1]

                ip_pid_dictionary = lists_to_dict(host_ips, host_pids)


                matches = find_matches(parsed_ip_list, host_ips)
                match_list = []
                if len(matches):
                    for match in matches:
                        match_list.append(match)
                else:
                    global flag
                    if flag == False:
                        print("\n [+] No active malicious IP connections detected")
                        animation_thread = threading.Thread(target=running_animation, daemon=True)
                        animation_thread.start()
                        flag = True

                for match in match_list:
                    pop_up_thread = threading.Thread(target=pop_up,args=(f"[+] Connection to know malicious IP detected!\n[+] IP: {match} ",))
                    pop_up_thread.start()
                    print(f" \n [!] ACTIVE CONNECTION TO KNOWN MALICIOUS IP DETECTED")
                    timestamp = get_timestamp()
                    print(timestamp)
                    print(f' [-] IP: {match} PID: {ip_pid_dictionary[match]}')
                    print(f' [+] Event logged to "Malicious-IP_Detector_log.csv"')
                    print(' [*] Process information: ')
                    pid_info = pid_info_printer(f'tasklist /FI "PID eq {ip_pid_dictionary[match]}" /V')
                    for line in pid_info:
                        print('    ' + line)
                    path_info = path_finder(f'wmic process where ProcessId={ip_pid_dictionary[match]} get ExecutablePath')
                    for path in path_info:
                        print('\n    Filepath: ' + path)
                        detection_hash = hash_host_malware(f'certutil -hashfile "{path}" SHA256')
                        print("    SHA256 Hash: " + detection_hash + '\n')
                    log_message_generator(match, pid_info, path, detection_hash)
                    pop_up_thread.join()
                time.sleep(30)
            except KeyboardInterrupt:
                sys.exit(0)
            except Exception as e:
                print(str(e))
                sys.exit(1)

if __name__ == "__main__":
    flag = False
    main()
