import os
import re
import subprocess
import datetime
import json
import validators
import requests
from tqdm import tqdm
from termcolor import colored

def load_config():
    with open('config/config.json', 'r') as config_file:
        config = json.load(config_file)
    return config

config = load_config()
SUSPICIOUS_CONSTANTS = config.get('SUSPICIOUS_CONSTANTS', [])
SUSPICIOUS_FUNCTIONS = config.get('SUSPICIOUS_FUNCTIONS', [])
SUSPICIOUS_KEYWORDS = config.get('SUSPICIOUS_KEYWORDS', [])

WEBHOOK_URL = 'here nigger'

def pwc(message, color="white"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colored_message = colored(f'[{timestamp}] {message}', color)
    print(colored_message)


def detect_suspicious_code(source_code):
    alerts = []

    for constant in SUSPICIOUS_CONSTANTS:
        if constant in source_code:
            alerts.append(f"Suspicious constant detected: {constant}")

    for func in SUSPICIOUS_FUNCTIONS:
        func_pattern = r'\b' + re.escape(func) + r'\b'
        if re.search(func_pattern, source_code):
            alerts.append(f"Suspicious function detected: {func}")

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in source_code:
            alerts.append(f"Suspicious code detected: {keyword}")

    return alerts


def detectob(source_code):
    alerts = []
    obfuscation_techniques = []

    if 'eval(' in source_code:
        alerts.append("Suspicious use of 'eval()' detected (dynamic code execution).")
        obfuscation_techniques.append("eval() usage")
    if 'exec(' in source_code:
        alerts.append("Suspicious use of 'exec()' detected (dynamic code execution).")
        obfuscation_techniques.append("exec() usage")
    
    b64pattern = r'[A-Za-z0-9+/=]{4,}'
    if re.search(b64pattern, source_code):
        alerts.append("Base64 encoded data detected (potentially obfuscated).")
        obfuscation_techniques.append("Base64 encoding")
    
    if re.search(r'chr\(\s*\d+\s*\)\s*\+\s*ord\(', source_code):
        alerts.append("Use of chr() and ord() detected (potentially obfuscated string construction).")
        obfuscation_techniques.append("chr() and ord() usage")

    obvarnames = re.findall(r'\b[a-zA-Z0-9_]{10,}\b', source_code)
    if obvarnames:
        alerts.append(f"Detected long variable names or obfuscation patterns: {', '.join(obvarnames)}")
        obfuscation_techniques.append("Long variable names")

    hcp = r'([0-9a-fA-F]{8,})'
    if re.search(hcp, source_code):
        alerts.append("Hidden constants detected (possible obfuscation).")
        obfuscation_techniques.append("Hidden constants")

    if re.search(r'"[^"]*"\s*\+\s*"[^"]*"', source_code) or re.search(r"'[^']*'\s*\+\s*'[^']*'", source_code):
        alerts.append("Suspicious string concatenation detected (obfuscation technique).")
        obfuscation_techniques.append("String concatenation via `+`")

    if re.search(r'\\x[0-9a-fA-F]{2}', source_code):
        alerts.append("Hexadecimal string representation detected (obfuscation technique).")
        obfuscation_techniques.append("Hexadecimal string representation")

    if 'globals(' in source_code or 'locals(' in source_code:
        alerts.append("Suspicious dynamic evaluation using globals() or locals() detected.")
        obfuscation_techniques.append("Dynamic evaluation via globals() or locals()")

    if 'lambda ' in source_code:
        alerts.append("Suspicious use of lambda functions detected (possible obfuscation).")
        obfuscation_techniques.append("Lambda functions")

    uncommon_identifier_pattern = r'\b[a-zA-Z0-9_]{15,}\b'
    uncommon_identifiers = re.findall(uncommon_identifier_pattern, source_code)
    if uncommon_identifiers:
        alerts.append(f"Suspicious random/uncommon identifiers detected: {', '.join(uncommon_identifiers)}")
        obfuscation_techniques.append("Random/uncommon identifiers")

    return alerts, obfuscation_techniques




def detect_suspicious_directory_access():
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')

    paths = {
        'Discord': roaming + '\\discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Lightcord': roaming + '\\Lightcord',
        'Discord PTB': roaming + '\\discordptb',
        'Opera GX': roaming + '\\Opera Software\\Opera GX Stable',
        'Chrome': local + '\\Google\\Chrome\\User Data\\Default',
        'Microsoft Edge': local + '\\Microsoft\\Edge\\User Data\\Default',
    }

    suspicious_directories = [
        '\\Google\\Chrome\\User Data', '\\Opera Software\\Opera Stable',
        '\\Discord', '\\DiscordCanary', '\\Microsoft\\Edge'
    ]

    alerts = []
    for app, path in paths.items():
        for suspicious_dir in suspicious_directories:
            if suspicious_dir.lower() in path.lower():
                alerts.append(f"Suspicious access detected to: {app} ({path})")

    return alerts


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


def urlcat(url):
    suspicious_keywords = ['.ru', '.xyz', 'bit.ly', 'short.ly', 'paypal', 'cryptocurrency', 't.me', 'discord']
    trusted_domains = ['pybit.lol']  # Replace with real trusted domains

    for keyword in suspicious_keywords:
        if keyword in url:
            return 'Suspicious'

    for domain in trusted_domains:
        if domain in url:
            return 'Internal'

    return 'External'


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
    try:
        result_pyc = subprocess.run([pycdas_executable, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with open(pycdas_log, 'w', encoding='utf-8') as log:
            log.write(result_pyc.stdout.decode('utf-8'))
    except subprocess.CalledProcessError as e:
        pwc(f"→ Error during pycdas decompilation: {e}", 'red')
        return None, None

    pwc("→ Decompiling using pycdc...", 'green')
    try:
        result_pyc = subprocess.run([pycdc_executable, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with open(pycdc_log, 'w', encoding='utf-8') as log:
            log.write(result_pyc.stdout.decode('utf-8'))
    except subprocess.CalledProcessError as e:
        pwc(f"→ Error during pycdc decompilation: {e}", 'red')
        return None, None

    return pycdas_log, pycdc_log


def sscatf(log_dir, alert_details):
    suspicious_code_alerts_file = os.path.join(log_dir, 'suspicious_code_alerts.txt')
    with open(suspicious_code_alerts_file, 'w', encoding='utf-8') as f:
        for alert in alert_details:
            f.write(f"{alert}\n")
    pwc(f"→ Suspicious code alerts saved to {suspicious_code_alerts_file}", 'green')
    return suspicious_code_alerts_file


def send_webhook(urls, log_dir, source_file, suspicious_code_alert_count, suspicious_code_alerts_file, obfuscation_status, obfuscation_techniques):
    urls_file_path = os.path.join(log_dir, 'urls_found.txt')
    with open(urls_file_path, 'w') as f:
        for url, category in urls:
            f.write(f"{url} ({category})\n")

    obfuscation_message = f"**Obfuscation detected:** ```js\nTrue```\n**Techniques used:**\n```{', '.join(obfuscation_techniques)}```" if obfuscation_status else "Obfuscation detected: False"
    suspicious_code_message = f"Suspicious code alerts count: {suspicious_code_alert_count}"

    embed = {
        "title": f"File Analyzed: {os.path.basename(source_file)}",
        "description": f"@everyone\n\n<a:Green_dot:1302184339831787520> Decompilation of `{source_file}` complete.\n\n"
                       f"<:8038boosterpurple:1264850372535652374> **URLs found:** ```js\n{len(urls)}```\n"
                       f"<:8038boosterpurple:1264850372535652374> **Suspicious Code Alerts Count:** ```js\n{suspicious_code_message}```\n"
                       f"<:8038boosterpurple:1264850372535652374> {obfuscation_message}\n"
                       f"<:8038boosterpurple:1264850372535652374> **Log directory:** ```js\n{log_dir}```",
        "color": 3066993,  # Blue color
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


def main():
    file_path = input("Drag and drop the .pyc file here: ")
    if not os.path.exists(file_path):
        print(f"Error: The file at {file_path} does not exist.")
        exit(1)

    # Decompile the file
    pycdas_log, pycdc_log = decomp(file_path)

    if pycdas_log and pycdc_log:
        urls = scan_logs_for_urls([pycdas_log, pycdc_log])
        suspicious_code_alert_details = []
        suspicious_code_alert_count = 0
        obfuscation_techniques = []
        obfuscation_status = False

        with open(pycdc_log, 'r', encoding='utf-8') as f:
            source_code = f.read()
            suspicious_code_alert_details = detect_suspicious_code(source_code)
            obalerts, techniques = detectob(source_code)
            suspicious_code_alert_details.extend(obalerts)  # Add obfuscation alerts to the list
            obfuscation_status = bool(techniques)
            obfuscation_techniques = techniques
            suspicious_code_alert_count = len(suspicious_code_alert_details)

        suspicious_code_alerts_file = sscatf(os.path.dirname(pycdas_log), suspicious_code_alert_details)
        send_webhook(urls, os.path.dirname(pycdas_log), file_path, suspicious_code_alert_count, suspicious_code_alerts_file, obfuscation_status, obfuscation_techniques)


if __name__ == "__main__":
    main()
