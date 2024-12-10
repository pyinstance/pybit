
try:
    import os
    import re
    import subprocess
    import datetime
    from tqdm import tqdm
    from termcolor import colored
    from jinja2 import Template
    import validators  # Import a URL validation library
except Exception as e:
    print(f"{e}")
    os.system("pip install -r assets/requirements.txt")
    os.system("cls")

# Function to print messages with a timestamp and color
def pwc(message, color="white"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colored_message = colored(f'[{timestamp}] {message}', color)
    print(colored_message)

# Function to decompile a .pyc file using pycdas and pycdc
def decomp(file_path):
    # Extract the filename without extension
    file_name = os.path.splitext(os.path.basename(file_path))[0]
    
    # Log files
    log_dir = os.path.join('logs', file_name)
    os.makedirs(log_dir, exist_ok=True)  # Create directory if it does not exist
    pycdas_log = os.path.join(log_dir, f'{file_name}_pycdas_log.txt')
    pycdc_log = os.path.join(log_dir, f'{file_name}_pycdc_log.txt')
    
    pycdas_executable = os.path.join('util/pycdas.exe')
    pycdc_executable = os.path.join('util/pycdc.exe')
    
    if not os.path.exists(pycdas_executable):
        pwc(f'Error: pycdas executable not found at {pycdas_executable}', 'red')
        return None, None
    
    if not os.path.exists(pycdc_executable):
        pwc(f'Error: pycdc executable not found at {pycdc_executable}', 'red')
        return None, None
    
    # Decompile using pycdas with a loading bar
    pwc("Decompiling using pycdas...", 'blue')
    with tqdm(total=100, desc="Decompiling using pycdas", unit="%") as pbar:
        try:
            result_pyc = subprocess.run([pycdas_executable, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with open(pycdas_log, 'w', encoding='utf-8') as log:
                log.write(result_pyc.stdout.decode('utf-8'))
            pbar.update(100)
        except subprocess.CalledProcessError as e:
            pwc(f"Error during pycdas decompilation: {e}", 'red')
            return None, None
    
    # Decompile using pycdc with a loading bar
    pwc("Decompiling using pycdc...", 'green')
    with tqdm(total=100, desc="Decompiling using pycdc", unit="%") as pbar:
        try:
            result_pyc = subprocess.run([pycdc_executable, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with open(pycdc_log, 'w', encoding='utf-8') as log:
                log.write(result_pyc.stdout.decode('utf-8'))
            pbar.update(100)
        except subprocess.CalledProcessError as e:
            pwc(f"Error during pycdc decompilation: {e}", 'red')
            return None, None

    return pycdas_log, pycdc_log

# Function to scan log files for webhooks, bot tokens, and other URLs
def scan_logs_for_urls(log_files):
    url_regex = r'https?://[^\s/$.?#].[^\s]*|discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9-]+|bot[o0]ken=[a-zA-Z0-9_-]+'
    results = []
    
    for log_file in log_files:
        pwc(f'Scanning {log_file} for URLs...', 'cyan')
        with open(log_file, 'r', encoding='utf-8') as log:
            content = log.read()
            urls = re.findall(url_regex, content)
            if urls:
                for url in urls:
                    if validators.url(url):  # Check if the URL is valid
                        results.append(url)
                        pwc(f'Found URL: {url}', 'green')
                    else:
                        # Skip invalid URLs without printing them
                        continue
            else:
                pwc(f'No URLs found in {log_file}.', 'white')

    return results

# Function to generate an HTML report
def genhtmlrep(urls, log_dir):
    # Load the HTML template
    template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pybit Decompiled Log URLs</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            line-height: 1.6; 
            background-color: #000; 
            color: #fff; 
            margin: 0; 
            padding: 0; 
            display: flex; 
            flex-direction: column; 
            align-items: center; 
            justify-content: center; 
            height: 100vh;
            overflow: auto;
            position: relative;
            z-index: 1;
        }
        h1 { 
            text-align: center; 
            color: #ffffff; 
            margin-bottom: 20px; 
            text-shadow: 0 0 15px white;
        }
        .container { 
            width: 90%; 
            margin: auto; 
            padding: 20px; 
            background-color: #000; 
            border-radius: 5px; 
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); 
            position: relative;
            z-index: 1;
            overflow-y: auto;
            max-height: 80vh;
            display: flex;
            flex-direction: column;
        }
        .loading { 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            position: absolute; 
            top: 50%; 
            left: 50%; 
            transform: translate(-50%, -50%);
            z-index: 10;
            display: none;
        }
        .loading::after { 
            content: ""; 
            display: inline-block; 
            width: 40px; 
            height: 40px; 
            border-radius: 50%; 
            border: 4px solid #fff; 
            border-top: 4px solid #ffffff; 
            animation: spin 1s linear infinite; 
        }
        ul { 
            list-style-type: none; 
            padding: 0; 
        }
        li { 
            margin: 10px 0; 
            padding: 15px; 
            background-color: #202020; 
            border-radius: 3px; 
            color: #fff; 
            cursor: pointer; 
            transition: background-color 0.3s, box-shadow 0.3s;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        li:hover { 
            background-color: #000; 
            box-shadow: 0 0 20px white; 
        }
        .link { 
            text-decoration: none; 
            color: inherit;
            display: block;
            width: 100%;
            height: 100%;
            padding: 0;
            margin: 0;
        }
        .search-bar {
            display: flex;
            justify-content: center;
            margin-bottom: 20px;
        }
        .search-input {
            width: 50%;
            padding: 5px;
            border: 2px solid #000;
            border-radius: 3px;
            outline: none;
            background-color: #202020;
            color: #fff;
            transition: border-color 0.3s;
        }
        .search-input:focus {
            border-color: #e74c3c;
        }
        .info-box {
            width: 30%;
            margin: 5px;
            padding: 10px;
            background-color: #333;
            border-radius: 5px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            color: #fff;
            display: flex;
            justify-content: space-between;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="loading animate__animated animate__fadeIn">Loading...</div>
        <h1>Pybit Decompiled Log URLs</h1>
        <div class="info-box">
            <span>File: {{ file_path }}</span>
        </div>
        <div class="info-box">
            <span>Compiler: Pyinstaller </span>
        </div>
        <div class="info-box">
            <span>Total Links: {{ totalLinks }}</span>
        </div>
        <div class="search-bar">
            <input type="text" id="search" class="search-input" placeholder="Search URLs...">
        </div>
        <ul id="urlList">
            {% if urls %}
                {% for url in urls %}
                <li class="url-item"><a href="{{ url }}" class="link">{{ url }}</a></li>
                {% endfor %}
            {% else %}
                <p>No URLs found.</p>
            {% endif %}
        </ul>
        <div class="info-box">
            <span>Number of Links: {{ number_of_links }}</span>
        </div>
    </div>
    <script>
        document.addEventListener("DOMContentLoaded", function() {
            document.querySelector('.loading').style.display = 'none';

            var searchInput = document.getElementById('search');
            searchInput.addEventListener('input', function() {
                var filter = searchInput.value.toLowerCase();
                var urls = document.querySelectorAll('.url-item');
                urls.forEach(function(link) {
                    var url = link.querySelector('.link').textContent.toLowerCase();
                    link.style.display = url.includes(filter) ? 'block' : 'none';
                });
            });

            // Display the number of links
            document.querySelector('.info-box span').textContent = `Number of Links: ${document.querySelectorAll('.url-item').length}`;
        });
    </script>
</body>
</html>
"""

    template = Template(template_str)
    html_content = template.render(urls=urls)
    html_file_path = os.path.join(log_dir, 'report.html')
    with open(html_file_path, 'w', encoding='utf-8') as html_file:
        html_file.write(html_content)

if __name__ == '__main__':
    file_path = input(colored('Enter the path of the .pyc file to decompile: ', 'white'))
    
    if not os.path.exists(file_path):
        pwc(f'Error: The file at {file_path} does not exist.', 'red')
        exit()
    
    pwc("Starting decompilation process...", 'blue')
    with tqdm(total=100, desc="Decompiling", unit="%", colour="cyan") as pbar:
        try:
            for _ in range(100):
                pbar.update(1)
            pycdas_log, pycdc_log = decomp(file_path)
        except Exception as e:
            pwc(f"Error: {e}", 'red')
            exit()

    if pycdas_log and pycdc_log:
        urls = scan_logs_for_urls([pycdas_log, pycdc_log])
        genhtmlrep(urls, os.path.dirname(pycdas_log))   