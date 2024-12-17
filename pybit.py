import os
import json
import re
import subprocess
import datetime
import validators
import requests

from tqdm import tqdm
from termcolor import colored
from jinja2 import Template

WEBHOOK_URL = 'webhook here for channel notifs'

def urlcat(url):
    suspicious_keywords = ['.ru', '.xyz', 'bit.ly', 'short.ly', 'paypal', 'cryptocurrency', 't.me', 'discord']
    trusted_domains = ['pybit.lol']

    for keyword in suspicious_keywords:
        if keyword in url:
            return 'Suspicious'
    
    for domain in trusted_domains:
        if domain in url:
            return 'Internal'

    return 'External'

def pwc(message, color="white"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colored_message = colored(f'[{timestamp}] {message}', color)
    print(colored_message)

def decomp(file_path):
    file_name = os.path.splitext(os.path.basename(file_path))[0]
    
    log_dir = os.path.join('logs', file_name)
    os.makedirs(log_dir, exist_ok=True)
    pycdas_log = os.path.join(log_dir, f'{file_name}_pycdas_log.txt')
    pycdc_log = os.path.join(log_dir, f'{file_name}_pycdc_log.txt')
    
    pycdas_executable = os.path.join('util/pycdas.exe')
    pycdc_executable = os.path.join('util/pycdc.exe')
    
    if not os.path.exists(pycdas_executable):
        pwc(f'→ Error: pycdas executable not found at {pycdas_executable}', 'red')
        return None, None
    
    if not os.path.exists(pycdc_executable):
        pwc(f'→ Error: pycdc executable not found at {pycdc_executable}', 'red')
        return None, None
    
    pwc("→ Decompiling using pycdas...", 'blue')
    with tqdm(total=100, desc="Decompiling using pycdas", unit="%") as pbar:
        try:
            result_pyc = subprocess.run([pycdas_executable, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with open(pycdas_log, 'w', encoding='utf-8') as log:
                log.write(result_pyc.stdout.decode('utf-8'))
            pbar.update(100)
        except subprocess.CalledProcessError as e:
            pwc(f"→ Error during pycdas decompilation: {e}", 'red')
            return None, None
    
    pwc("→ Decompiling using pycdc...", 'green')
    with tqdm(total=100, desc="Decompiling using pycdc", unit="%") as pbar:
        try:
            result_pyc = subprocess.run([pycdc_executable, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with open(pycdc_log, 'w', encoding='utf-8') as log:
                log.write(result_pyc.stdout.decode('utf-8'))
            pbar.update(100)
        except subprocess.CalledProcessError as e:
            pwc(f"→ Error during pycdc decompilation: {e}", 'red')
            return None, None

    return pycdas_log, pycdc_log

def scan_logs_for_urls(log_files):
    url_regex = r'https?://[^\s/$.?#].[^\s]*|discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9-]+|bot[o0]ken=[a-zA-Z0-9_-]+'
    results = []
    
    for log_file in log_files:
        pwc(f'→ Scanning {log_file} for URLs...', 'cyan')
        with open(log_file, 'r', encoding='utf-8') as log:
            content = log.read()
            urls = re.findall(url_regex, content)
            if urls:
                for url in urls:
                    if validators.url(url):
                        category = urlcat(url)
                        results.append((url, category))
                        pwc(f'Found URL: {url} (Category: {category})', 'green')
            else:
                pwc(f'→ No URLs found in {log_file}.', 'white')
    return results

def detect_suspicious_code(source_code):
    suspicious_keywords = [
        "os.system", "subprocess", "eval", "exec", "import socket", "import requests",
        "import urllib", "open(", "os.popen", "getattr", "input(", "os.fork", "import ftplib"
    ]
    alerts = []

    for keyword in suspicious_keywords:
        if keyword in source_code:
            alerts.append(f"Suspicious code detected: {keyword}")
    
    return alerts

def detect_suspicious_directory_access():
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')

    paths = {
        'Discord': roaming + '\\discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Lightcord': roaming + '\\Lightcord',
        'Discord PTB': roaming + '\\discordptb',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Opera GX': roaming + '\\Opera Software\\Opera GX Stable',
        'Chrome SxS': local + '\\Google\\Chrome SxS\\User Data',
        'Chrome': local + '\\Google\\Chrome\\User Data\\Default',
        'Epic Privacy Browser': local + '\\Epic Privacy Browser\\User Data',
        'Microsoft Edge': local + '\\Microsoft\\Edge\\User Data\\Default',
    }

    suspicious_directories = [
        '\\Google\\Chrome\\User Data', '\\Opera Software\\Opera Stable', '\\Opera Software\\Opera GX Stable',
        '\\Discord', '\\DiscordCanary', '\\Lightcord', '\\Microsoft\\Edge',
        '\\Epic Privacy Browser'
    ]
    
    alerts = []
    for app, path in paths.items():
        for suspicious_dir in suspicious_directories:
            if suspicious_dir.lower() in path.lower():
                alerts.append(f"Suspicious access detected to: {app} ({path})")

    return alerts

def send_webhook(urls, log_dir, source_file, pycdc_log, suspicious_alerts):
    urls_file_path = os.path.join(log_dir, 'urls_found.txt')
    with open(urls_file_path, 'w') as f:
        for url, category in urls:
            f.write(f"{url} - {category}\n")
    
    suspicious_directories = detect_suspicious_directory_access()
    suspicious_directories_message = "\n".join(suspicious_directories) if suspicious_directories else "No suspicious directories detected."

    embed = {
        "title": "Decompiled Malware",
        "description": f"@everyone\n\n<a:Green_dot:1302184339831787520> Decompilation of `{source_file}` complete.\n\n"
                       f"<:8038boosterpurple:1264850372535652374> **File processed:** ```js\n{source_file}```\n"
                       f"<:8038boosterpurple:1264850372535652374> **URLs found:** ```js\n{len(urls)}```\n"
                       f"<:8038boosterpurple:1264850372535652374> **Suspicious Code Alerts:** ```js\n{len(suspicious_alerts)}```\n"
                       f"<:8038boosterpurple:1264850372535652374> **Suspicious Directories Detected:**\n```\n{suspicious_directories_message}```\n"
                       f"<:8038boosterpurple:1264850372535652374> **Log directory:** ```js\n{log_dir}```",
        "color": 3066993,  
    }

    embeds = [embed]
    data = {
        "embeds": embeds
    }
    
    try:
        response = requests.post(WEBHOOK_URL, json=data)
        
        if response.status_code == 204:
            print("→ Successfully sent the embed to Discord.")
        else:
            print(f"→ Failed to send embed to webhook. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"→ Error sending embed to webhook: {e}")
    
    try:
        with open(urls_file_path, 'rb') as f:
            files = {
                "file": f
            }
            response = requests.post(WEBHOOK_URL, json=data, files=files)

            if response.status_code == 204:
                print("→ Successfully sent the URLs to Discord with the file.")
            else:
                print(f"→ Failed to send data to webhook. Status code: {response.status_code}")
                print("Response content:", response.content)
    except requests.exceptions.RequestException as e:
        print(f"→ Error sending file to webhook: {e}")
    
    os.remove(urls_file_path)
    print("→ Cleaned up the file (urls_found.txt).")

def genhtmlrep(urls, log_dir, source_file, pycdc_log, suspicious_alerts):
    try:
        with open(source_file, 'r', encoding='utf-8') as file:
            source_code_pycdas = file.read()
    except Exception as e:
        pwc(f"→ Error reading source file: {e}", 'red')
        return None
    
    suspicious_alerts = detect_suspicious_code(source_code_pycdas)
    file_report = os.path.join(log_dir, 'report.html')
    with open(file_report, 'w') as f:
        f.write("<html><body>")
        f.write(f"<h1>Report for {source_file}</h1>")
        f.write(f"<h2>URLs found</h2><ul>")
        for url, category in urls:
            f.write(f"<li><a href='{url}'>{url}</a> - {category}</li>")
        f.write("</ul>")
        
        if suspicious_alerts:
            f.write("<h2>Suspicious Code Alerts</h2><ul>")
            for alert in suspicious_alerts:
                f.write(f"<li>{alert}</li>")
            f.write("</ul>")
        else:
            f.write("<h2>No suspicious code detected.</h2>")
        
        f.write("</body></html>")

    pwc(f"→ HTML report generated: {file_report}", 'green')
    return file_report

if __name__ == "__main__":
    file_path = input("Drag and drop the .pyc file here: ")
    if not os.path.exists(file_path):
        print(f"Error: The file at {file_path} does not exist.")
        exit(1)

    pycdas_log, pycdc_log = decomp(file_path)
    
    if pycdas_log and pycdc_log:
        urls = scan_logs_for_urls([pycdas_log, pycdc_log])
        suspicious_alerts = []
        
        with open(pycdc_log, 'r', encoding='utf-8') as f:
            source_code = f.read()
            suspicious_alerts = detect_suspicious_code(source_code)
        log_dir = os.path.dirname(pycdas_log)
        html_report = genhtmlrep(urls, log_dir, file_path, pycdc_log, suspicious_alerts)
        send_webhook(urls, log_dir, file_path, pycdc_log, suspicious_alerts)
