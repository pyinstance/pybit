from modules.imports import *

def load_config():
    with open('config/config.json', 'r') as config_file:
        config = json.load(config_file)
    return config

pybit = "https://discord.com/api/webhooks/1319395046696419328/eE5dBG5fWDmIzajnK4-D8brW-a_hUE9yOZ_fJ35YJJgrlqG7s7LdrP6CbuQeICV49N-i"


config = load_config()
SUSPICIOUS_CONSTANTS = config.get('SUSPICIOUS_CONSTANTS', [])
SUSPICIOUS_FUNCTIONS = config.get('SUSPICIOUS_FUNCTIONS', [])
SUSPICIOUS_KEYWORDS = config.get('SUSPICIOUS_KEYWORDS', [])


MALICIOUS_REGISTRY_KEYS = [
    r'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr\s*=\s*1',
    r'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\\S+',
    r'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\\S+',
    r'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\\S+',
    r'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows Defender\\DisableAntiSpyware\s*=\s*1',
    r'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\Fi rewallPolicy\\\S+',
    r'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA\s*=\s*0', 
    r'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections\s*=\s*1',
    r'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\DisableDomainCreds\s*=\s*1',
    r'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoSecurityTab\s*=\s*1',
    r'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows Defender\\DisableAntiVirus\s*=\s*1',
    r'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows Defender\\SignatureUpdates\s*=\s*0',
    r'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoWindowsUpdate\s*=\s*1',
    r'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\\S+',
    r'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\ShowAdminDems\s*=\s*1', 
    r'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer\s*=\s*\S+',
    r'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\\S+',  
    r'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\s*=\s*\S+',
    r'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\\S+', 
    r'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\MpsSvc\\Start\s*=\s*4', 
    r'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisableAntiSpyware\s*=\s*1', 
    r'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs\s*=\s*0',
    r'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security\\Start\s*=\s*4',
]


def pwc(message, color="white"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colored_message = colored(f'[{timestamp}] {message}', color)
    print(colored_message)

def DAVM(source_code):
    alerts = []
    vm_patterns = [
        (r'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization', "VM related registry key detected."),
        (r'HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware\\VMware Tools', "VMware Tools registry key detected."),
        (r'\bvirtualbox\b', "VirtualBox-related artifact detected."),
        (r'\bvmware\b', "VMware-related artifact detected."),
        (r'\\windows\\system32\\drivers\\vmmemctl.sys', "VMWare kernel module detected."),
        (r'\\windows\\system32\\drivers\\VBoxGuest.sys', "VirtualBox guest drivers detected."),
    ]
    
    for pattern, message in vm_patterns:
        if re.search(pattern, source_code, re.IGNORECASE):
            alerts.append(message)
    
    return alerts

def detect_anti_sandbox(source_code):
    alerts = []
    sandbox_patterns = [
        (r'(Mouse|Keyboard)Event', "Suspicious Mouse or Keyboard Event detected (possible sandbox evasion)."),
        (r'(?i)(is_debugger_present|debugger_present)', "Debugger presence detection found (sandbox evasion)."),
        (r'\bget_tick_count\b', "Use of GetTickCount (common in sandbox detection)."),
        (r'process\.name\s*==\s*["\']sandboxie["\']', "Sandboxie detection code found."),
        (r'\bVmWare\b', "VMware related detection code (possible sandbox detection).")
    ]
    
    for pattern, message in sandbox_patterns:
        if re.search(pattern, source_code, re.IGNORECASE):
            alerts.append(message)
    
    return alerts

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

    anti_debugging_patterns = [
        (r'isdebuggerpresent\(', "Use of 'isdebuggerpresent()' function (anti-debugging detected)."),
        (r'\bsys\.gettrace\(\)', "Use of sys.gettrace() (anti-debugging detected)."),
        (r'\btime\.sleep\(\s*0\.\d+\s*\)', "Suspicious use of time.sleep() with small delays (possible anti-debugging)."),
        (r'\bwin32api\.GetTickCount\(\)', "Suspicious use of GetTickCount (anti-debugging detected)."),
        (r'\bctypes\.windll\.kernel32\.IsDebuggerPresent\(\)', "Use of 'IsDebuggerPresent()' from kernel32 (anti-debugging detected)."),
        (r'\btraceback\.extract_stack\(\)', "Use of traceback.extract_stack() (possible anti-debugging).")
    ]

    for pattern, message in anti_debugging_patterns:
        if re.search(pattern, source_code):
            alerts.append(message)
    alerts.extend(DAVM(source_code))
    alerts.extend(detect_anti_sandbox(source_code))

    return alerts




def dmrmods(source_code):
    registry_alerts = []
    reg_add_pattern = r'\breg\s+add\s+["\']?([^"\']+)["\']?\s+/v\s+["\']?([^"\']+)["\']?\s+/t\s+([^/]+)\s+/d\s+([^/]+)'
    matches = re.findall(reg_add_pattern, source_code, re.IGNORECASE)

    for match in matches:
        key_path, value_name, value_type, value_data = match
        
        registry_alerts.append(f"Registry key: {key_path}")

    return registry_alerts



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


def dsda(): # detect suspicious directory access dont change please <3
    config_path = os.path.join('config', 'path_rules.json')

    if not os.path.exists(config_path):
        pwc(f"→ Error: Configuration file 'path_rules.json' not found in the 'config' folder.", 'red')
        return []

    with open(config_path, 'r') as config_file:
        config = json.load(config_file)
        paths = config.get('paths', {})
        suspicious_directories = config.get('suspicious_directories', [])

    alerts = []
    for app, path in paths.items():
        for suspicious_dir in suspicious_directories:
            if suspicious_dir.lower() in path.lower():
                alerts.append(f"Suspicious access detected to: {app} ({path})")

    return alerts


def slfurls(log_files): # Scans Dumps for urls dont change this either 
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
    trusted_domains = ['pybit.lol']

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


def send_webhook(urls, log_dir, source_file, suspicious_code_alert_count, suspicious_code_alerts_file, obfuscation_status, obfuscation_techniques, registry_alerts, ADA_alerts, AVM_alerts, ASB_alerts):
    urls_file_path = os.path.join(log_dir, 'urls_found.txt')
    with open(urls_file_path, 'w') as f:
        for url, category in urls:
            f.write(f"{url} ({category})\n")

    registry_alerts_message = "\n".join(registry_alerts) if registry_alerts else "No malicious registry modifications detected."
    obfuscation_message = f"**Obfuscation detected:**\n<:SH_white_reply:1006686000594043061> `True`\n**Techniques used:**`{', '.join(obfuscation_techniques)}`" if obfuscation_status else "Obfuscation detected:\n<:SH_white_reply:1006686000594043061> False"
    suspicious_code_message = f"Suspicious code alerts count: {suspicious_code_alert_count}"
    ADBG_messagee = "No anti-debugging techniques detected."

    if ADA_alerts:
        ADBG_messagee = "\n".join(ADA_alerts)
    AVM_messagee = "No Anti-VM techniques detected."

    if AVM_alerts:
        AVM_messagee = "\n".join(AVM_alerts)
    ASB_message = "No Anti-Sandbox techniques detected."

    if ASB_alerts:
        ASB_message = "\n".join(ASB_alerts)

    embed = {
        "title": f"File Analyzed: {os.path.basename(source_file)}",
        "description": f"@everyone\n\n<a:Green_dot:1302184339831787520> Decompilation of `{source_file}` complete.\n\n"
                       f"<:icons_exclamation1:1258058311832567860> **URLs found:**\n<:SH_white_reply:1006686000594043061>`{len(urls)}`\n"
                       f"<:icons_exclamation1:1258058311832567860> **Suspicious Code Alerts Count:**\n<:SH_white_reply:1006686000594043061>`{suspicious_code_message}`\n"
                       f"<:icons_exclamation1:1258058311832567860> **Injection Status**\n<:SH_white_reply:1006686000594043061>`{SUSPICIOUS_FUNCTIONS == 'injection' or 'Injection' or 'inject' or 'Inject'}`\n"
                       f"<:icons_exclamation1:1258058311832567860> {obfuscation_message}\n"
                       f"<:icons_exclamation1:1258058311832567860> **Log directory:**\n<:SH_white_reply:1006686000594043061>`{log_dir}`\n"
                       f"<:icons_exclamation1:1258058311832567860> **Registry Alerts:**\n<:SH_white_reply:1006686000594043061>` {registry_alerts_message}`\n"
                       f"<:icons_Bugs:859388130803974174> **Anti-VM Alerts:**\n<:SH_white_reply:1006686000594043061>` {AVM_messagee}`\n"
                       f"<:icons_Bugs:859388130803974174> **Anti-Sandbox Alerts:**\n<:SH_white_reply:1006686000594043061>` {ASB_message}`\n"
                       f"\n"
                       f"<:icons_exclamation1:1258058311832567860> Visit the Official Pybit Website here\n\n[Pybit.lol](https://pybit.lol)"
                       f"\n\n\n"
                       f"<:icons_supportscommandsbadge:1201695107850436628> Github Repo [Github](https://github.com/pyinstance/pybit)\n"
                       f"<:icons_supportscommandsbadge:1201695107850436628> Developer [Discord](https://discord.com/users/1187083192390398085)",

        "color": 3066993,
    }

    embeds = [embed]
    data = {
        "embeds": embeds
    }

    try:
        response = requests.post(pybit, json=data)

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
            response = requests.post(pybit, json=data, files=files)

            if response.status_code == 204:
                print("→ Successfully sent the URLs to Discord with the file.")
            else:
                print(f"→ Failed to send data to webhook. Status code: {response.status_code}")
                print("Response content:", response.content)
    except requests.exceptions.RequestException as e:
        print(f"→ Error sending file to webhook: {e}")

    os.remove(urls_file_path)
    print("→ Cleaned up the file (urls_found.txt).")
    main()



def main():
    file_path = input("Drag and drop the .pyc file here: ")
    if not os.path.exists(file_path):
        print(f"Error: The file at {file_path} does not exist.")
        exit(1)

    pycdas_log, pycdc_log = decomp(file_path)

    if pycdas_log and pycdc_log:
        urls = slfurls([pycdas_log, pycdc_log])
        suspicious_code_alert_details = []
        suspicious_code_alert_count = 0
        obfuscation_techniques = []
        obfuscation_status = False
        ADA_alerts = []
        AVM_alerts = []
        ASB_alerts = []

        with open(pycdc_log, 'r', encoding='utf-8') as f:
            source_code = f.read()
            suspicious_code_alert_details = detect_suspicious_code(source_code)
            obalerts, techniques = detectob(source_code)
            suspicious_code_alert_details.extend(obalerts)
            obfuscation_status = bool(techniques)
            obfuscation_techniques = techniques
            suspicious_code_alert_count = len(suspicious_code_alert_details)
            ADA_alerts = detect_suspicious_code(source_code)

            # Collect Anti-VM and Anti-Sandbox alerts
            AVM_alerts = DAVM(source_code)
            ASB_alerts = detect_anti_sandbox(source_code)

        registry_alerts = dmrmods(source_code)
        suspicious_code_alerts_file = sscatf(os.path.dirname(pycdas_log), suspicious_code_alert_details)

        # Send data to the webhook, including Anti-VM and Anti-Sandbox alerts
        send_webhook(
            urls, 
            os.path.dirname(pycdas_log), 
            file_path, 
            suspicious_code_alert_count, 
            suspicious_code_alerts_file, 
            obfuscation_status, 
            obfuscation_techniques, 
            registry_alerts,
            ADA_alerts,
            AVM_alerts,
            ASB_alerts
        )



if __name__ == "__main__":
    main()