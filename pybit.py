from libs.libs import *
from modules.colors import *

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
sys.stderr = open(os.devnull, 'w')

logs_folder = "logs"
if not os.path.exists(logs_folder):
    os.makedirs(logs_folder)

log_file_path = os.path.join(logs_folder, 'processes.log')

logging.basicConfig(filename=log_file_path, level=logging.INFO, format='%(asctime)s - %(message)s')

logging.getLogger('tensorflow').setLevel(logging.ERROR)
logging.getLogger('usb_service_win').setLevel(logging.CRITICAL)
logging.getLogger().setLevel(logging.CRITICAL)

def betterprint(message, color="white"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    color_codes = {
        "white": "\033[0m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "red": "\033[31m",
        "blue": "\033[34m",
        "cyan": "\033[36m",
        "magenta": "\033[35m",
        "bold": "\033[1m",
        "underline": "\033[4m"
    }
    color_code = color_codes.get(color, "\033[0m")
    print(f"{color_code}[{timestamp}] {message}\033[0m")

def globtextt(driver):
    try:
        log_box = WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.ID, "logBox"))
        )
        log_text = log_box.get_attribute("value")
        betterprint(f"Log Output:\n{log_text}", "blue")
    except Exception as e:
        betterprint(f"Error grabbing log text: {e}", "red")

def save_file_to_family(file_name, family_name):
    families_folder = "families"
    if not os.path.exists(families_folder):
        os.makedirs(families_folder)

    family_file_path = os.path.join(families_folder, f"{family_name}.json")
    
    if os.path.exists(family_file_path):
        with open(family_file_path, 'r') as f:
            family_data = json.load(f)
    else:
        family_data = {}

    if family_name not in family_data:
        family_data[family_name] = []
    
    family_data[family_name].append(file_name)

    with open(family_file_path, 'w') as f:
        json.dump(family_data, f, indent=4)
    
    betterprint(f"File '{file_name}' has been added to family '{family_name}'", "green")

def decomppyc():
    util_folder = "util"
    if not os.path.exists(util_folder):
        betterprint(f"└———> Error: The 'util' folder does not exist.", "red")
        return

    pyc_files = [f for f in os.listdir(util_folder) if f.endswith('.pyc')]
    
    if not pyc_files:
        betterprint(f"└———> No .pyc files found in the 'util' folder.", "red")
        return

    betterprint("└———> Found the following .pyc files:", "blue")
    for idx, file in enumerate(pyc_files, 1):
        betterprint(f"{idx}. {file}", "yellow")

    try:
        choice = int(input("└———> Choose a .pyc file by number to decompile: ")) - 1
        if choice < 0 or choice >= len(pyc_files):
            betterprint(f"└———> Invalid choice.", "red")
            return

        pyc_file = pyc_files[choice]
        pyc_file_path = os.path.join(util_folder, pyc_file)

        log_folder = "logs/decompile"
        if not os.path.exists(log_folder):
            os.makedirs(log_folder)

        log_file = os.path.join(log_folder, "log.txt")
        
        with open(log_file, 'w') as log:
            result = subprocess.run(["util/pycdas", pyc_file_path], stdout=log, stderr=log)

        if result.returncode == 0:
            betterprint(f"└———> Successfully decompiled {pyc_file}. Output saved in {log_file}", "green")
        else:
            betterprint(f"└———> Error during decompilation of {pyc_file}. Check the log for details.", "red")

        webhookfinder(log_file)

    except ValueError:
        betterprint(f"└———> Invalid input, please enter a number.", "red")
    except Exception as e:
        betterprint(f"└———> Error during pyc decompilation: {e}", "red")

def webhookfinder(log_file):
    ddwregex = r"https://discord\.com/api/webhooks/\d+/[\w-]+"
    
    with open(log_file, 'r') as f:
        log_content = f.read()
    
    webhooks = re.findall(ddwregex, log_content)
    
    if webhooks:
        for webhook in webhooks:
            betterprint(f"Found Discord Webhook: {webhook}", "cyan")
    else:
        betterprint("No Discord webhook found in the log file.", "yellow")
os.system('cls')
print(water("""
                     __        __    __     
                    /  |      /  |  /  |    
  ______   __    __ $$ |____  $$/  _$$ |_   
 /      \ /  |  /  |$$      \ /  |/ $$   |  
/$$$$$$  |$$ |  $$ |$$$$$$$  |$$ |$$$$$$/   
$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ | __ 
$$ |__$$ |$$ \__$$ |$$ |__$$ |$$ |  $$ |/  |
$$    $$/ $$    $$ |$$    $$/ $$ |  $$  $$/ 
$$$$$$$/   $$$$$$$ |$$$$$$$/  $$/    $$$$/  
$$ |      /  \__$$ |                        
$$ |      $$    $$/                         
$$/        $$$$$$/                                                            
"""))
print("""
└———> Dev : dns
      └———> pybit Discord Malware Detector / webhook finder   
""")
betterprint("[ALERT] AFTER PYBIT HAS DOWNLOADED THE EXTRACTED ZIP MAKE SURE TO PUT ALL OF THE PYC FILES INSIDE OF THE UTIL FOLDER BEFORE DECOMPILING PYC", "yellow")
file_path = input("└———> Drag File to Decompile to this terminal: ")

if not os.path.exists(file_path):
    betterprint(f"└———> Error: The file at {file_path} does not exist.", "red")
    exit()

family_name = input("└———> Enter the family name you'd like to put the executable under: ")

save_file_to_family(file_path, family_name)

options = webdriver.ChromeOptions()
options.add_argument('--headless')
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')

try:
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
except Exception as e:
    betterprint(f"└———> Error initializing the Chrome driver: {e}", "red")
    exit()

url = "https://pyinstxtractor-web.netlify.app/"
try:
    driver.get(url)
except Exception as e:
    betterprint(f"Error navigating to the website: {e}", "red")
    driver.quit()
    exit()

try:
    upload_element = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='file']"))
    )
    upload_element.send_keys(file_path)
    betterprint(f"└———> Uploaded file from {file_path}", "green")
except Exception as e:
    betterprint(f"└———> Error locating the file input element or uploading file: {e}", "red")
    driver.quit()
    exit()

try:
    process_button = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Process')]"))
    )
    process_button.click()
    betterprint("└———> Currently Processing the Executable", "blue")
except Exception as e:
    betterprint(f"└———> Error clicking Process button: {e}", "red")
    driver.quit()
    exit()

try:
    download_button = WebDriverWait(driver, 20).until(
        EC.presence_of_element_located((By.XPATH, "//a[contains(text(), 'Download')]"))
    )
    download_url = download_button.get_attribute('href')
    download_filename = os.path.basename(urllib.parse.urlparse(download_url).path)
    betterprint(f"Download URL found: {download_url}", "cyan")
    betterprint(f"Extracted file name: {download_filename}", "yellow")

    download_path = os.path.join(os.getcwd(), download_filename)
    os.system(f"curl -o {download_path} {download_url}")
    betterprint(f"Downloaded file to {download_path}", "green")
except Exception as e:
    betterprint(f"└———> Extracted Data in downloads dir", "green")
    time.sleep(2)
    betterprint(f"└———> Possible pyc Entry points will have the extention (.pyc)", "yellow")
    decompile_choice = input("└———> Would you like to decompile the .pyc files? (yes/no): ").strip().lower()

if decompile_choice == 'yes':
    decomppyc()
