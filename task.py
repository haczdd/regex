import os
import re
import json
import csv
from bs4 import BeautifulSoup

server_logs = 'server_logs.txt'
web_server = 'index.html'

logs_directory = 'logs'
os.makedirs(logs_directory, exist_ok=True)

failed_logins = os.path.join(logs_directory, 'failed_logins.json')
log_analysis_txt = os.path.join(logs_directory, 'log_analysis.txt')
log_analysis_csv = os.path.join(logs_directory, 'log_analysis.csv')
combined_security_data = os.path.join(logs_directory, 'combined_security_data.json')
threat_ips_json = os.path.join(logs_directory, 'threat_ips.json')

with open(server_logs, 'r') as f:
    file = f.read()

pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) .*?" (\d{3})'
matches = re.findall(pattern, file)

status_code_per_ip = {}
all_ips = set()

for match in matches:
    ip, date, method, status_code = match
    all_ips.add(ip)  
    if status_code == '401':
        if ip in status_code_per_ip:
            status_code_per_ip[ip]['count'] += 1
        else:
            status_code_per_ip[ip] = {'date': date, 'method': method, 'count': 1}

for ip, details in status_code_per_ip.items():
    count = details['count']
    date = details['date']
    method = details['method']

    if count > 5:
        try:
            with open(failed_logins, "r") as file:
                existing_data = json.load(file)
        except FileNotFoundError:
            existing_data = {}

        existing_data[ip] = count

        with open(failed_logins, "w") as file:
            json.dump(existing_data, file, indent=4)
    if count > 0:
        try:
            with open(combined_security_data, "r") as file:
                existing_data = json.load(file)
        except FileNotFoundError:
            existing_data = {}

        if ip not in existing_data:
            existing_data[ip] = count

        with open(combined_security_data, "w") as file:
            json.dump(existing_data, file, indent=4)
        
    with open(log_analysis_txt, 'a') as file:
        out = f'This IP: {ip} ignored {count} times.!\n'
        file.write(out)

with open(log_analysis_csv, 'a', newline='', encoding='utf-8') as csvfile:
    csvwriter = csv.writer(csvfile)
    if csvfile.tell() == 0:
        csvwriter.writerow(['IP ünvanı', 'Tarix', 'HTTP metodu', 'Uğursuz cəhdlər'])

    for ip, details in status_code_per_ip.items():
        csvwriter.writerow([ip, details['date'], details['method'], details['count']])

with open(web_server, 'r', encoding='utf-8') as file:
    soup = BeautifulSoup(file, 'html.parser')

threat_ips = []
rows = soup.find_all('tr')
for row in rows[1:]:
    cells = row.find_all('td')
    if len(cells) > 0:
        thread_ip = cells[0].text.strip()
        if thread_ip in all_ips: 
            threat_ips.append(thread_ip)

ip_data = {"Threat_IPs": threat_ips}

with open(threat_ips_json, 'w', encoding='utf-8') as json_file:
    json.dump(ip_data, json_file, indent=4)

print(f"Bütün fayllar '{logs_directory}' qovluğuna yazıldı.")
