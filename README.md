![Pybit](https://i.imgur.com/NvN7vVn.png)

**PyBit** is a powerful, Python-based tool for detecting and protecting against Discord-related malware before it can be executed. It automatically detects malicious webhooks, decompiles both executable files and `.pyc` files, and provides a clear insight into the inner workings of potentially dangerous files. This tool is designed for developers, security professionals, and anyone who wants to ensure the integrity and safety of their systems by inspecting and mitigating malware threats.

---

## Features

- 🕵️‍♂️ **Webhook Detection:** Automatically detects Discord webhooks embedded within malicious code, alerting the user to potential threats.
- 🛠️ **Executable Analysis:** Decompiles and analyzes Windows executables (.exe files), identifying hidden malware code that might otherwise be difficult to spot.
- 🐍 **PYC File Decompiling:** Decompiles `.pyc` files, often used in Python-based malware, to allow users to inspect malicious code and identify vulnerabilities.
- 👨‍💻 **User-Friendly Interface:** Minimal user input required, providing easy-to-understand output and warnings that help mitigate security risks.
- 🚀 **Fast Processing:** Quickly scans files and outputs results, making it easy to scan multiple files in short bursts.
- 🔒 **Security-Centered:** Focused on detecting malicious behavior commonly associated with Discord malware, particularly related to webhook usage.

---

## Screenshots

![PyBit Screenshot](https://i.imgur.com/Y8JVp0e.png)
![Decompiled Code Log](https://i.imgur.com/WG8AkeS.png)

*Above: Example of PyBit scanning an executable file for malicious code.*

---

## Installation

**if you have python installed follow these steps**
   - RUN installation batch file called **start.bat**
   - Once this has been ran and finished the file will execute 
   ## Please make sure you READ EVERYTHING THE PROGRAM IS TELLING YOU

   ## ALSO IF YOU DO NOT HAVE PYTHON INSTALLED AND WANT TO JUST DOWNLOAD THE COMPILED EXECUTABLE THEN 
   ## HEAD OVER TO RELEASES AND DOWNLOAD THE LATEST VERSION

### Prerequisites

- **Python 3.11.0** or higher (we recommend Python 3.11.0 for compatibility with all dependencies).
- **Git** (for cloning the repository).

If you don't have Python installed, download it from the official website:

[Download Python 3.11.0](https://www.python.org/downloads/release/python-3110/)

### Step-by-Step Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your-username/pybit.git
   cd pybit
