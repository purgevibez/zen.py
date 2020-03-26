import requests, random, re, time, threading, os, sys, getpass
from colorama import init
import ctypes
from urllib.parse import urlencode
import ssl, socket
from time import sleep
from threading import Thread

import atexit, requests, hashlib, random
import os, sys, requests, socket, timeit
import readchar, hmac, uuid, os, string
import json

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

init()
RED = "\033[1;31;40m"
GREEN = "\033[1;32;40m"
BLUE = "\033[1;36;40m"
WHITE = "\033[1;37;40m"
MAGENTA = "\033[1;35;40m"
YELLOW  = "\033[1;33;40m"
DB  = "\033[1;34;40m"
ERROR = "[\x1b[31m-\x1b[39m]"
SUCCESS = "[\x1b[32m+\x1b[39m]"
INPUT = "[\x1b[33m?\x1b[39m]"
INFO = "[\x1b[35m*\x1b[39m]"

IG_EDIT_PROFILE = "{{\"gender\":\"3\",\"username\":\"{}\",\"first_name\":\"Swapped By Vibez\",\"email\":\"{}\"}}"
IG_LOGIN_ACTUAL = "{{\"username\":\"{}\",\"device_id\":\"{}\",\"password\":\"{}\",\"login_attempt_count\":\"0\"}}"
BREAK = 3
LINE_FEED = 13
BACK_SPACE = 127 if os.name == "posix" else 8

IG_API_CONTENT_TYPE = "application/x-www-form-urlencoded; charset=UTF-8"
IG_API_USER_AGENT = "Instagram 124.0.0.17.473 Android (28/9; 280dpi; 720x1382; samsung; SM-A105FN; a10; exynos7885; en_US; 192992565)"


def random_id(length):
        return "".join(random.choice(string.digits) for _ in range(length))
class Signatures(object):
        def __init__(self):
                super(Signatures, self).__init__()
                self.key = b"02271fcedc24c5849a7505120650925e2b4c5b041e0a0bb0f82f4d41cfcdc944"

        def gen_uuid(self):
                return str(uuid.uuid4())

        def gen_device_id(self):
                return "android-{}".format(hashlib.md5(self.gen_uuid().encode("utf-8")).hexdigest()[:16])

        def gen_signature(self, data):
                return hmac.new(self.key, str.encode(data), hashlib.sha256).hexdigest()

        def sign_post_data(self, data):
                return "signed_body={}.{}&ig_sig_key_version=4".format(self.gen_signature(data), data)

class Device(object):
        def __init__(self):
                super(Device, self).__init__()
                self.filepath = os.path.expanduser("~/.madara-turbo.ini")

                if (os.path.isfile(self.filepath)):
                        if (self.read_ini(self.filepath)):
                                return

                self.create_device_ini()
                self.write_ini(self.filepath)

        def create_device_ini(self):
                self.adid = Signatures().gen_uuid()
                self.uuid = Signatures().gen_uuid()
                self.phone_id = Signatures().gen_uuid()
                self.device_id = Signatures().gen_device_id()

        def read_ini(self, filename):
                lines = [line.rstrip("\r\n") for line in open(filename, "r")]

                for line in lines:
                        if (line.startswith("adid=")):
                                self.adid = line.split("=")[1]
                        elif (line.startswith("uuid=")):
                                self.uuid = line.split("=")[1]
                        elif (line.startswith("phoneid=")):
                                self.phone_id = line.split("=")[1]
                        elif (line.startswith("deviceid=")):
                                self.device_id = line.split("=")[1]

                return None not in (self.adid, self.uuid, self.phone_id, self.device_id)

        def write_ini(self, filename):
                print("; Madara's Instagram Turbo", file=open(filename, "w"))
                print("; Information used for device identification\r\n", file=open(filename, "a"))
                print("[Device]\r\nadid={}\r\nuuid={}".format(self.adid, self.uuid), file=open(filename, "a"))
                print("phoneid={}\r\ndeviceid={}".format(self.phone_id, self.device_id), file=open(filename, "a"))

class Instagram(object):
        def __init__(self):
                super(Instagram, self).__init__()
                self.device = Device()
                self.url = "https://i.instagram.com/api/v1"

                self.attempts = 0
                self.rs = 0
                self.running = True
                self.s = requests.Session()
                self.logged_in = False
                self.session_id = None

                self.email = None
                self.username = None
                self.spam_blocked = False
                self.rate_limited = False
                self.missed_swap = False
                self.claimed = False

        def login(self, username, password):
                response = requests.post(self.url + "/accounts/login/", headers={
                        "Accept": "*/*",
                        "Accept-Encoding": "gzip, deflate",
                        "Accept-Language": "en-US",
                        "User-Agent": IG_API_USER_AGENT,
                        "Content-Type": IG_API_CONTENT_TYPE,
                        "X-IG-Capabilities": "3brTvw==",
                        "X-IG-Connection-Type": "WIFI"
                }, data=Signatures().sign_post_data(IG_LOGIN_ACTUAL.format(
                        username, self.device.device_id, password
                )))

                if (response.status_code == 200):
                        self.session_id = response.cookies["sessionid"]

                response = response.json()

                if (response["status"] == "fail"):
                        if (response["message"] == "challenge_required"):
                                print("{} Please verify this login and make sure 2FA is disabled".format(ERROR))
                        else:
                                print("{} {}".format(ERROR, response["message"]))
                elif (response["status"] == "ok"):
                        self.logged_in = True

                        if (self.get_profile_info()):
                                #print("{} Successfully logged in".format(SUCCESS))
                                return self.logged_in
                        else:
                                print("{} Successfully logged in but failed to fetch profile information, this may be due to a rate limit".format(ERROR))
                else:
                        print("{} An unknown login error occured".format(ERROR))

                return False

        def logout(self):
                if (not self.logged_in):
                        return False

                return "\"status\": \"ok\"" in requests.post(self.url + "/accounts/logout/", headers={
                        "Accept": "*/*",
                        "Accept-Encoding": "gzip, deflate",
                        "Accept-Language": "en-US",
                        "User-Agent": IG_API_USER_AGENT,
                        "Content-Type": IG_API_CONTENT_TYPE,
                        "X-IG-Capabilities": "3brTvw==",
                        "X-IG-Connection-Type": "WIFI"
                }, cookies={
                        "sessionid": self.session_id
                }).text

        def update_consent(self):
                response = requests.post(self.url + "/consent/update_dob/", headers={
                        "Accept": "*/*",
                        "Accept-Encoding": "gzip, deflate",
                        "Accept-Language": "en-US",
                        "User-Agent": IG_API_USER_AGENT,
                        "Content-Type": IG_API_CONTENT_TYPE,
                        "X-IG-Capabilities": "3brTvw==",
                        "X-IG-Connection-Type": "WIFI"
                }, data=Signatures().sign_post_data(
                        "{\"current_screen_key\":\"dob\",\"day\":\"1\",\"year\":\"1998\",\"month\":\"1\"}"
                ), cookies={
                        "sessionid": self.session_id
                })

                if ("\"status\": \"ok\"" in response.text):
                        print("{} Successfully updated consent to GDPR".format(SUCCESS))
                        return self.get_profile_info()

                print("{} Failed to consent to GDPR, use an IP that is not from Europe".format(ERROR))
                return False

        def get_profile_info(self):
                response = requests.get(self.url + "/accounts/current_user/?edit=true", headers={
                        "Accept": "*/*",
                        "Accept-Encoding": "gzip, deflate",
                        "Accept-Language": "en-US",
                        "User-Agent": IG_API_USER_AGENT,
                        "X-IG-Capabilities": "3brTvw==",
                        "X-IG-Connection-Type": "WIFI"
                }, cookies={
                        "sessionid": self.session_id
                })

                if ("\"consent_required\"" in response.text):
                        return self.update_consent()
                elif ("few minutes" in response.text):
                        return False

                response = response.json()
                self.email = response["user"]["email"]
                self.username = response["user"]["username"]

                return self.email is not None and self.username is not None

        def build_claim_data(self):
                self.claim_data = Signatures().sign_post_data(IG_EDIT_PROFILE.format(self.target, self.email))


        def claim_target(self):
                response = self.s.post(self.url + "/accounts/edit_profile/", headers={
                        "Accept": "*/*",
                        "connection": "keep-alive",
                        "Accept-Encoding": "gzip, deflate",
                        "Accept-Language": "en-US",
                        "User-Agent": IG_API_USER_AGENT,
                        "Content-Type": IG_API_CONTENT_TYPE,
                        #"X-IG-Capabilities": "3brTvw==",
                        #"X-IG-Connection-Type": "WIFI"
                }, cookies={
                        "sessionid": self.session_id
                }, data=self.claim_data)

                if ("feedback_required" in response.text):
                        self.spam_blocked = True
                if ("This username isn't available." in response.text):
                    print(response)

                return "\"status\": \"ok\"" in response.text


class turbo:

    def __init__(self):
        self.attempt = 0
        self.claimed = False
        self.instagram = Instagram()

    def gather_data(self):
        print("[-]Vibez Swap | Modified ZEN Swap".format(WHITE, WHITE, WHITE, WHITE))
        self.username = input("[+]Username: ".format(INPUT))  
        self.password = input("[+]Password: ".format(INPUT))   # get_input("{} Password: ".format(INPUT), True)
        if (not self.instagram.login(self.username, self.password)):
                    print("[+]@{} [FAIL]".format(WHITE, username))
        else:
                    print("[+]Successfully logged in!".format(WHITE)
                    )
    def api(self):
        if (not self.instagram.login(self.username, self.password)):
            print("{}api failed to login".format(WHITE))
            input("")
            os._exit(0)

    def get_input(prompt, mask=False):
        ret_str = b""
        print(prompt, end="", flush=True)

        while (True):
            ch = readchar.readchar()

            if (os.name == "posix"):
                ch = str.encode(ch)

            code_point = ord(ch)

            if (code_point == BREAK):  # Ctrl-C
                if (os.name == "posix"):
                    print("\r\n", end="", flush=True)

                exit(0)
            elif (code_point == LINE_FEED):  # Linefeed
                break
            elif (code_point == BACK_SPACE):  # Backspace
                if (len(ret_str) > 0):
                    ret_str = ret_str[:-1]
                    print("\b \b", end="", flush=True)
            else:
                ret_str += ch
                print("*" if mask else ch.decode("utf-8"), end="", flush=True)

        print("\r\n", end="", flush=True)
        return ret_str.decode("utf-8")

    def main(self):
        self.s = requests.session()
        
        urll = 'https://www.instagram.com/accounts/login/ajax/'

        bh = {
            'user-agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36',
        }
            
        login = self.s.get('https://www.instagram.com/accounts/login/', headers=bh)
            
        bcookies = login.cookies.get_dict()
        h = {
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.9',
                'content-length': '53',
                'content-type': 'application/x-www-form-urlencoded',
                'cookie': 'rur={}; mid={}; csrftoken={}'.format(bcookies['rur'], bcookies['mid'], bcookies['csrftoken'],),
                'origin': 'https://www.instagram.com/',
                'referer': 'https://www.instagram.com/accounts/emailsignup/',
                'user-agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36',
                'x-csrftoken': self.s.cookies.get('csrftoken'),
                #'x-ig-app-id': '936619743392459',
                #'x-instagram-ajax': '79d0a43d9853',
                'x-requested-with': 'XMLHttpRequest',
        }
        payload = {
            'username': self.username,
            'password': self.password,
            'queryParams': {},
        }
                
        auth = self.s.post(urll, headers=h, data=payload)
        if "checkpoint_url" in auth.json().keys():
            print("[+]Accept sus: {}{}{}".format(WHITE, WHITE, WHITE, auth.json()['checkpoint_url'], WHITE))
            input("")
        elif auth.json()['authenticated']:
            pass

        else:
            print("[+]failed auth on @{}{}".format(WHITE, WHITE, self.username, WHITE))
            input("")
            os._exit(0)
        self.api()
        
        ah = {
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.9',
                #'cookie': 'mid={}; sessionid={}; csrftoken={}; ds_user_id={}; rur={}; urlgen={}'.format(self.s.cookies.get('mid'), self.s.cookies.get('sessionid'), self.s.cookies.get('csrftoken'), self.s.cookies.get('ds_user_id'), self.s.cookies.get('rur'), self.s.cookies.get('urlgen')),
                'referer': 'https://www.instagram.com/accounts/edit/',
                'user-agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36',
                'x-csrftoken': self.s.cookies.get('csrftoken'),
                'x-requested-with': 'XMLHttpRequest',
        }
        
        try:
            profile = self.s.get('https://instagram.com/accounts/edit/?__a=1', headers=ah)
            userinfo = profile.json()['form_data']
        except:
            print("[+]The account is rate limited or num locked..{}".format(WHITE, WHITE, WHITE))
            input("")
            os._exit(0)
        self.target = input('[+]Target: ')
        self.payload = urlencode({
            'first_name': 'Vibez!',
            'email': userinfo['email'],
            'username': self.target,
            'phone_number': userinfo['phone_number'],
            'biography': '',
            'external_url': 'instagram.com/vibez.purge/',
            'chaining_enabled': 'on',
        })
        self.instagram.target = self.target
        self.check()
        threads = input('[+]Threads: ')
        self.instagram.build_claim_data()
        #print(requests.post('https://www.instagram.com/accounts/edit/', headers=self.ph, data=self.payload, hooks={'response': self.check_status}))
        print("[+]Threads successfully Loaded".format(WHITE, WHITE))

        input("\npress enter to begin your swap...".format(WHITE))

        self.start_time = time.time()
        
        for i in range(int(threads)):
            time.sleep(.001) #1ms sleep (give time to submit profile)
            threading.Thread(target=self.post_www).start()
            threading.Thread(target=self.post_i).start()
        while self.attempt < 300:
            time.sleep(.50)
            
        if self.claimed:
            input("close your window by pressing enter")
            os._exit(0)
        else:
            print('Missed...'.format(WHITE, WHITE, WHITE))
            input("")
            os._exit(0)

    def http_requests(self, host, headers, data=None):
            #Connect and init
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.load_default_certs()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, 443))
            sock = context.wrap_socket(sock, server_hostname=host)
            request = ""
            body = ""

            # commit headers
            for head in headers:
                request += (head + "\n")
            request += "\n"
            # print(request)
            if data is not None:
                request += (data + "\n\n")
            sock.send(request.encode())

            while True:
                bit = sock.recv(512)
                # print(bit)
                raw = bit.decode()
                if not bit: break
                body += raw

            sock.close()

            return body[body.find("\r\n\r\n") + 4:]
        
    def post_i(self):
        r = self.instagram.claim_target()
        self.attempt += 1
        if self.claimed or r:
            pass
        elif self.instagram.spam_blocked:
            print("[+]Spam Blocked...".format(WHITE, self.attempt))

    def check(self):
        response = self.http_requests('instagram.com', [
        'POST /accounts/edit/ HTTP/1.1',
        'Host: instagram.com',
        'accept: */*',
        'accept-encoding: gzip, deflate, br',
        'accept-language: en-US,en;q=0.9',
        'content-length: '+ str(len(self.payload)),
        'content-type: application/x-www-form-urlencoded',
        'cookie: mid={}; sessionid={}; csrftoken={}; ds_user_id={}; rur={}; urlgen={}'.format(self.s.cookies.get('mid'), self.s.cookies.get('sessionid'), self.s.cookies.get('csrftoken'), self.s.cookies.get('ds_user_id'), self.s.cookies.get('rur'), self.s.cookies.get('urlgen')),
        'origin: https://www.instagram.com/',
        'referer: https://www.instagram.com/accounts/edit/',
        'user-agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36',
        'x-csrftoken: ' + self.s.cookies.get('csrftoken'),
        'x-requested-with: XMLHttpRequest',
        'connection: close',
        ], data=self.payload)

        if "This username isn't available. Please try another." in response:
            print("[+]This user is swappable. \n".format(WHITE))
        elif "This username isn't available." in response:
            print("[+]This user isn't swappable. \n".format(WHITE))
            input(" close your window by pressing enter")
            os._exit(0)
        elif ("feedback_required" in response.text):
            print("[+]Spam Blcoked".format(WHITE))
            input(" close your window by pressing enter")
            os._exit(0)

    def post_www(self):
        response = self.http_requests('instagram.com', [
        'POST /accounts/edit/ HTTP/1.1',
        'Host: instagram.com',
        'accept: */*',
        'accept-encoding: gzip, deflate, br',
        'accept-language: en-US,en;q=0.9',
        'content-length: '+ str(len(self.payload)),
        'content-type: application/x-www-form-urlencoded',
        'cookie: mid={}; sessionid={}; csrftoken={}; ds_user_id={}; rur={}; urlgen={}'.format(self.s.cookies.get('mid'), self.s.cookies.get('sessionid'), self.s.cookies.get('csrftoken'), self.s.cookies.get('ds_user_id'), self.s.cookies.get('rur'), self.s.cookies.get('urlgen')),
        'origin: https://www.instagram.com/',
        'referer: https://www.instagram.com/accounts/edit/',
        'user-agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36',
        'x-csrftoken: ' + self.s.cookies.get('csrftoken'),
        'x-requested-with: XMLHttpRequest',
        'connection: close',
        ], data=self.payload)
        self.attempt += 1
        if "\"status\": \"ok\"" in response:
            status = "ok"
            print(response)
        if "This username isn't available." in response:
            status = "fail"
            print(response)
        elif "blocked" in response:
            status = "blocked"
            print(response)
        else:
            status = ''
        if self.claimed:
            pass
        elif "\"status\": \"ok\"" in response:
            self.claimed = True
            self.claimtime = time.time() - self.start_time
            print("\n\n[X]Username Updated:{}@{}{}\n\n[X]Speed:{}{}{}\n".format(SUCCESS, SUCCESS, self.target, SUCCESS, SUCCESS, SUCCESS, self.attempt/self.claimtime, SUCCESS))
        elif status == "blocked":
            print("{} {} [blocked] / www".format(ERROR, self.attempt))


                
t = turbo()
t.gather_data()
t.main()
