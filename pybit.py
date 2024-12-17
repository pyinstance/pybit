import os
import re
import subprocess
import datetime
import validators
import requests

from tqdm import tqdm
from termcolor import colored
from jinja2 import Template


# replace with your webhook this is for notifications for decompiled stubs ect
WEBHOOK_URL = 'https://discord.com/api/webhooks/1318357611636195390/2z8f7npvnEPW6AxreupOg8_H3qUZHXM6eKGj3rrYLBqrMtVo-Iv4AJg2hfL_6YG8oD7e'

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
                        results.append(url)
                        pwc(f'Found URL: {url}', 'green')
            else:
                pwc(f'→ No URLs found in {log_file}.', 'white')

    return results

import json

def send_webhook(urls, log_dir, source_file):
    urls_file_path = os.path.join(log_dir, 'urls_found.txt')
    with open(urls_file_path, 'w') as f:
        for url in urls:
            f.write(url + '\n')
    embed = {
        "title": "Decompiled Malware",
        "description": f"@everyone\n\n<a:Green_dot:1302184339831787520> Decompilation of `{source_file}` complete.\n\n"
                       f"<:8038boosterpurple:1264850372535652374> **File processed:** ```js\n{source_file}```\n"
                       f"<:8038boosterpurple:1264850372535652374> **URLs found:** ```js\n{len(urls)}```\n"
                       f"<:8038boosterpurple:1264850372535652374> **Log directory:** ```js\n{log_dir}```",
        "color": 3066993,  # Blue color
    }
    embeds = [embed]
    pwc(f"→ Embed data being sent: {json.dumps(embeds, indent=2)}", 'blue')
    data = {
        "embeds": embeds
    }
    try:
        response = requests.post(WEBHOOK_URL, json=data)
        
        if response.status_code == 204:
            pwc("→ Successfully sent the embed to Discord.", 'green')
        else:
            pwc(f"→ Failed to send embed to webhook. Status code: {response.status_code}", 'red')
            print("Response content:", response.content)
    except requests.exceptions.RequestException as e:
        pwc(f"→ Error sending embed to webhook: {e}", 'red')
    try:
        with open(urls_file_path, 'rb') as f:
            files = {
                "file": f
            }
            response = requests.post(WEBHOOK_URL, json=data, files=files)

            if response.status_code == 204:
                pwc("→ Successfully sent the URLs to Discord with the file.", 'green')
            else:
                pwc(f"→ Failed to send data to webhook. Status code: {response.status_code}", 'red')
                print("Response content:", response.content)
    except requests.exceptions.RequestException as e:
        pwc(f"→ Error sending file to webhook: {e}", 'red')
    os.remove(urls_file_path)
    pwc("→ Cleaned up the file (urls_found.txt).", 'green')


def genhtmlrep(urls, log_dir, source_file, pycdc_log):
    try:
        with open(source_file, 'r', encoding='utf-8') as file:
            source_code_pycdas = file.read()
    except Exception as e:
        source_code_pycdas = f"Error reading source file: {e}"
    try:
        with open(pycdc_log, 'r', encoding='utf-8') as file:
            source_code_pycdc = file.read()
    except Exception as e:
        source_code_pycdc = f"Error reading PyCDC log file: {e}"
    
    template_str = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="description" content="Pybit Decompiled Log URLs - View and analyze decompiled Python code">
        <title>Pybit Decompiled Log URLs</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css">
        <style>
            :root {
                --bg-primary: #030712;
                --bg-secondary: #111827;
                --bg-hover: #1f2937;
                --text-primary: #f8fafc;
                --text-secondary: #94a3b8;
                --accent: #3b82f6;
                --accent-hover: #2563eb;
                --accent-gradient: linear-gradient(135deg, #3b82f6, #8b5cf6);
                --glow-1: #3b82f6;
                --glow-2: #8b5cf6;
                --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
                --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1);
                --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1);
            }

            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: system-ui, -apple-system, sans-serif;
                line-height: 1.5;
                background-color: var(--bg-primary);
                color: var(--text-primary);
                min-height: 100vh;
                position: relative;
                overflow-x: hidden;
            }

            body::before,
            body::after {
                content: '';
                position: fixed;
                width: 300px;
                height: 300px;
                border-radius: 50%;
                filter: blur(100px);
                opacity: 0.15;
                pointer-events: none;
                animation: float 10s infinite alternate ease-in-out;
            }

            body::before {
                background: var(--glow-1);
                top: -100px;
                left: -100px;
                animation-delay: -2s;
            }

            body::after {
                background: var(--glow-2);
                bottom: -100px;
                right: -100px;
            }

            @keyframes float {
                0% {
                    transform: translate(0, 0) scale(1);
                }
                100% {
                    transform: translate(50px, 50px) scale(1.2);
                }
            }

            .container {
                max-width: 72rem;
                margin: 0 auto;
                padding: clamp(1rem, 5vw, 2rem);
                position: relative;
                z-index: 1;
            }

            .header {
                text-align: center;
                margin-bottom: clamp(2rem, 5vw, 3rem);
                padding: clamp(1rem, 3vw, 2rem);
                position: relative;
            }

            .header::before {
                content: '';
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                width: 150px;
                height: 150px;
                background: var(--accent);
                filter: blur(100px);
                opacity: 0.1;
                pointer-events: none;
            }

            .header-content {
                display: inline-flex;
                align-items: center;
                gap: 0.75rem;
                position: relative;
            }

            .header-content::after {
                content: '';
                position: absolute;
                bottom: -0.5rem;
                left: 50%;
                transform: translateX(-50%);
                width: 50%;
                height: 2px;
                background: var(--accent-gradient);
                border-radius: 1rem;
                box-shadow: 0 0 10px var(--accent);
            }

            .header-title {
                font-size: clamp(1.5rem, 5vw, 2.5rem);
                font-weight: 800;
                background: var(--accent-gradient);
                -webkit-background-clip: text;
                background-clip: text;
                color: transparent;
                text-shadow: 0 0 30px rgba(59, 130, 246, 0.5);
                letter-spacing: -0.025em;
            }

            .card {
                background-color: rgba(17, 24, 39, 0.7);
                border-radius: 1rem;
                overflow: hidden;
                box-shadow: var(--shadow-lg),
                            0 0 20px rgba(59, 130, 246, 0.1);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                position: relative;
            }

            .card::before {
                content: '';
                position: absolute;
                inset: 0;
                background: linear-gradient(to bottom right,
                            rgba(59, 130, 246, 0.1),
                            rgba(139, 92, 246, 0.1));
                pointer-events: none;
            }

            .tabs {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                gap: 0.25rem;
                padding: 0.5rem;
                background-color: rgba(0, 0, 0, 0.3);
                position: relative;
                z-index: 1;
            }

            .tab {
                padding: 0.75rem 1rem;
                background: rgba(255, 255, 255, 0.03);
                border: 1px solid rgba(255, 255, 255, 0.1);
                color: var(--text-secondary);
                cursor: pointer;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                border-radius: 0.5rem;
                font-size: 0.875rem;
                font-weight: 500;
                backdrop-filter: blur(10px);
            }

            .tab.active {
                background: var(--accent-gradient);
                color: white;
                font-weight: 600;
                box-shadow: 0 0 15px rgba(59, 130, 246, 0.3);
                border: none;
            }

            .tab:hover:not(.active) {
                background-color: rgba(255, 255, 255, 0.1);
                color: var(--text-primary);
                border-color: var(--accent);
            }

            .tab-content {
                padding: clamp(1rem, 3vw, 1.5rem);
                display: none;
                animation: slideIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
            }

            .tab-content.active {
                display: block;
            }

            .url-list {
                list-style: none;
                display: flex;
                flex-direction: column;
                gap: 0.75rem;
            }

            .url-item {
                background-color: rgba(255, 255, 255, 0.03);
                border-radius: 0.75rem;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                border: 1px solid rgba(255, 255, 255, 0.1);
                position: relative;
                overflow: hidden;
            }

            .url-item:hover {
                background-color: rgba(255, 255, 255, 0.05);
                transform: translateY(-2px);
                box-shadow: 0 0 20px rgba(59, 130, 246, 0.1);
                border-color: var(--accent);
            }

            .url-item::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: linear-gradient(45deg,
                            transparent,
                            rgba(59, 130, 246, 0.1),
                            transparent);
                transform: translateX(-100%);
                transition: transform 0.5s;
            }

            .url-item:hover::before {
                transform: translateX(100%);
            }

            .url-link {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 1rem;
                color: var(--text-secondary);
                text-decoration: none;
                gap: 1rem;
                word-break: break-all;
                position: relative;
                z-index: 1;
            }

            .url-link:hover {
                color: var(--text-primary);
            }

            .code-block {
                background-color: rgba(0, 0, 0, 0.5);
                border-radius: 0.75rem;
                overflow: hidden;
                border: 1px solid rgba(255, 255, 255, 0.1);
                position: relative;
            }

            .code-block::before {
                content: '';
                position: absolute;
                inset: 0;
                background: linear-gradient(45deg,
                            transparent,
                            rgba(59, 130, 246, 0.05),
                            transparent);
                pointer-events: none;
            }

            pre[class*="language-"] {
                margin: 0;
                padding: clamp(1rem, 3vw, 1.5rem);
                max-height: 70vh;
                overflow: auto;
                scrollbar-width: thin;
                scrollbar-color: var(--accent) var(--bg-secondary);
                background: transparent !important;
                position: relative;
                z-index: 1;
            }

            pre[class*="language-"]::-webkit-scrollbar {
                width: 8px;
                height: 8px;
            }

            pre[class*="language-"]::-webkit-scrollbar-track {
                background: rgba(0, 0, 0, 0.2);
            }

            pre[class*="language-"]::-webkit-scrollbar-thumb {
                background: var(--accent);
                border-radius: 4px;
            }

            pre[class*="language-"]::-webkit-scrollbar-thumb:hover {
                background: var(--accent-hover);
            }

            .empty-state {
                text-align: center;
                padding: clamp(2rem, 5vw, 3rem);
                color: var(--text-secondary);
            }

            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: translateY(10px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            @media (max-width: 640px) {
                .tabs {
                    grid-template-columns: 1fr;
                }

                .url-link {
                    flex-direction: column;
                    align-items: flex-start;
                }

                body::before,
                body::after {
                    width: 200px;
                    height: 200px;
                }
            }

            @media (prefers-reduced-motion: reduce) {
                .tab-content,
                .url-item,
                body::before,
                body::after,
                .url-item::before {
                    animation: none;
                    transition: none;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header class="header">
                <div class="header-content">
                    <h1 class="header-title">Pybit Decompiled Log URLs</h1>
                </div>
            </header>
            <main class="card">
                <div class="tabs" role="tablist">
                    <button class="tab active" role="tab" aria-selected="true" aria-controls="urls-panel">URLs</button>
                    <button class="tab" role="tab" aria-selected="false" aria-controls="pycdas-panel">Source Code (PyCDAS)</button>
                    <button class="tab" role="tab" aria-selected="false" aria-controls="pycdc-panel">Source Code (PyCDC)</button>
                </div>
                <div class="tab-content active" id="urls-panel">
                    <ul class="url-list">
                        {% for url in urls %}
                        <li class="url-item">
                            <a href="{{ url }}" class="url-link" target="_blank" rel="noopener noreferrer">{{ url }}</a>
                        </li>
                        {% endfor %}
                    </ul>
                </div>
                <div class="tab-content" id="pycdas-panel">
                    <div class="code-block">
                        <pre><code class="language-python">{{ source_code_pycdas }}</code></pre>
                    </div>
                </div>
                <div class="tab-content" id="pycdc-panel">
                    <div class="code-block">
                        <pre><code class="language-python">{{ source_code_pycdc }}</code></pre>
                    </div>
                </div>
            </main>
        </div>
        <script>
            document.addEventListener("DOMContentLoaded", function() {
                const tabs = document.querySelectorAll('.tab');
                const contents = document.querySelectorAll('.tab-content');

                tabs.forEach((tab, index) => {
                    tab.addEventListener('click', () => {
                        tabs.forEach(t => {
                            t.classList.remove('active');
                            t.setAttribute('aria-selected', 'false');
                        });
                        contents.forEach(c => c.classList.remove('active'));

                        tab.classList.add('active');
                        tab.setAttribute('aria-selected', 'true');
                        contents[index].classList.add('active');
                    });
                });
            });
        </script>
    </body>
    </html>
    """
    template = Template(template_str)
    html_content = template.render(urls=urls, source_code_pycdas=source_code_pycdas, source_code_pycdc=source_code_pycdc)

    html_file_path = os.path.join(log_dir, "decompiled_report.html")
    try:
        with open(html_file_path, 'w', encoding='utf-8') as file:
            file.write(html_content)
        pwc(f"→ HTML report generated: {html_file_path}", 'green')
    except Exception as e:
        pwc(f"→ Failed to generate HTML report: {e}", 'red')

if __name__ == '__main__':
    file_path = input("Drag and drop the .pyc file here: ")
    if not os.path.exists(file_path):
        print(f"Error: The file at {file_path} does not exist.")
        exit(1)

    pycdas_log, pycdc_log = decomp(file_path)
    
    if pycdas_log and pycdc_log:
        urls = scan_logs_for_urls([pycdas_log, pycdc_log])
        genhtmlrep(urls, os.path.dirname(pycdas_log), file_path, pycdc_log)
        log_dir = os.path.dirname(pycdas_log)
        source_file = file_path
        
        send_webhook(urls, log_dir, source_file)
    else:
        print("Error: Decompilation failed.")
