## Box Info

![Cerberus](https://github.com/0xRyies/HTB_Active/assets/60355031/42b999fe-8f77-423b-81c0-bc73bd1e63ef)

## Recon 
### Nmap
![image](https://github.com/0xRyies/HTB_Active/assets/60355031/c69f8bf8-fe29-4876-9d45-833662613214)

Nmap found one open port `8080` running `Apache 2.4.52` and it's redirecting to `icinga.cerberus.local `, so let's add that to our `/etc/hosts` and view the web app

### Viewing the web app

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/18dc3b2f-8042-414b-97a2-a1113ab2ca54)

we can search for `IcingaWeb 2` vulnerabilities

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/f3c16f14-02e2-4549-9c38-c9a310c0981f)

there's a file disclosure vulnerability with the `CVE-2022-24716`, so let's try it out!

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/a0390583-5e5d-4a37-8cc6-f85cffdc9a8d)

and it's working, but what can we do with it? I tried searching for IcingaWeb 2 default config file locations and found [This](https://wiki.archlinux.org/title/Icinga) article, I checked these files but the most important one was the `resources.ini`

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/03537395-de8e-437a-888f-2eff6b514d9b)

It had `matthew` password, so let's try this out on the login portal 

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/5da4f310-a195-4c56-847c-a4f9b7184a57)

and we are in! after playing around with the dashboard I found nothing really useful except for this password 

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/861465d2-7cf2-46c2-bae2-5d5bc777c500)

but that wasn't very handy, so I tried searching for an authenticated vulnerability, and found [This](https://github.com/JacobEbben/CVE-2022-24715) repo that had a PoC for `CVE-2022-24715` that allows an authenticated user for an RCE, let's try it

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/2004aa10-cdd2-4de0-b5ca-5081e47a6ecf)

and we have a shell as `www-data`, we can upgrade our shell using `python3 -c 'import pty;pty.spawn("/bin/bash")'` and move on. 

if we tried `ifconfig`

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/fd6c79ad-ae2c-4d6e-9cad-491a8fced4ae)

looks like we are in a type of sandboxed environment with the IP `172.16.22.2` , after playing around the machine I ended up running linpeas and found that we are in a `firejail` sandbox, so we can check for the version

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/d0ea7153-2715-440a-bdf2-6fb821a8679a)

and that's actually vulnerable to `CVE-2022-31214` that allows us to get a root shell!

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/36b61dd6-e383-49c1-8f67-ec45f5e7f088)

since we are now root, we can play around more, while hanging around in the /etc/ directory I found something called sssd which was weird enough for me to look at

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/c995f86a-43f0-4c5b-be43-d636c62511fc)

`SSSD is a system daemon. Its primary function is to provide access to local or remote identity and authentication resources through a common framework that can provide caching and offline support to the system.`
so this might be useful! I quickly searched for Linux active directory pentest and found this on [hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-active-directory)  

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/84754748-a1c9-4f2a-97c0-2a0f27cdfc34)

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/9b663ef0-3f01-41ca-b1f2-3d0dea2caf0d)

sadly, the secrets.mkey file was missing so I couldn't run the script, but instead, I went to discover `/var/lib/sss` more. 
to my surprise I found this 
```
root@icinga:/var/lib/sss/db# strings cache_cerberus.local.ldb
strings cache_cerberus.local.ldb
TDB file
&DN=CN=SUDORULES,CN=CUSTOM,CN=CERBERUS.LOCAL,CN=SYSDB
cn=sudorules,cn=custom,cn=cerberus.local,cn=sysdb
sudorules
sudoLastFullRefreshTime
1677760424
&DN=@INDEX:OBJECTCLASS:ID_MAPPING
@INDEX:OBJECTCLASS:ID_MAPPING
@IDXVERSION
@IDX
objectSID=S-1-5-21-4088429403-1159899800-2753317549,cn=id_mappings,cn=cerberus.local,cn=sysdb
&DN=@INDEX:NAME:cerberus.local
@INDEX:NAME:cerberus.local
@IDXVERSION
@IDX
objectSID=S-1-5-21-4088429403-1159899800-2753317549,cn=id_mappings,cn=cerberus.local,cn=sysdb
&DN=OBJECTSID=S-1-5-21-4088429403-1159899800-2753317549,CN=ID_MAPPINGS,CN=CERBERUS.LOCAL,CN=SYSDB
objectSID=S-1-5-21-4088429403-1159899800-2753317549,cn=id_mappings,cn=cerberus.local,cn=sysdb
name
cerberus.local
objectClass
id_mapping
objectSID
S-1-5-21-4088429403-1159899800-2753317549
slice
8705
&DN=CN=CERBERUS.LOCAL,CN=SYSDB
cn=cerberus.local,cn=sysdb
cerberus.local
site
Default-First-Site-Name
flatName
CERBERUS
domainID
S-1-5-21-4088429403-1159899800-2753317549
memberOfForest
cerberus.local
realmName
CERBERUS.LOCAL
site
Default-First-Site-Name
DN=@INDEX:CN:SUDORULES
@INDEX:CN:SUDORULES
@IDXVERSION
@IDX
cn=sudorules,cn=custom,cn=cerberus.local,cn=sysdb
DN=CN=SUDORULES,CN=C
&DN=@INDEX:CN:SUDORULES
@INDEX:CN:SUDORULES
@IDXVERSION
@IDX
cn=sudorules,cn=custom,cn=cerberus.local,cn=sysdb
&DN=@INDEX:CN:CERTMAP
@INDEX:CN:CERTMAP
@IDXVERSION
@IDX
cn=certmap,cn=sysdb
&DN=CN=CERTMAP,CN=SYSDB
cn=certmap,cn=sysdb
certmap
userNameHint
FALSE
&DN=@INDEX:NAME:matthew@cerberus.local
@INDEX:NAME:matthew@cerberus.local
@IDXVERSION
@IDX
name=matthew@cerberus.local,cn=users,cn=cerberus.local,cn=sysdb
&DN=@INDEX:LASTUPDATE:1677672476
@INDEX:LASTUPDATE:1677672476
@IDXVERSION
@IDX
name=matthew@cerberus.local,cn=users,cn=cerberus.local,cn=sysdb
&DN=@INDEX:GIDNUMBER:1000
@INDEX:GIDNUMBER:1000
@IDXVERSION
@IDX
name=matthew@cerberus.local,cn=users,cn=cerberus.local,cn=sysdb
&DN=@INDEX:UIDNUMBER:1000
@INDEX:UIDNUMBER:1000
@IDXVERSION
@IDX
name=matthew@cerberus.local,cn=users,cn=cerberus.local,cn=sysdb
&DN=@INDEX:DATAEXPIRETIMESTAMP:0
@INDEX:DATAEXPIRETIMESTAMP:0
@IDXVERSION
@IDX
name=matthew@cerberus.local,cn=users,cn=cerberus.local,cn=sysdb
&DN=NAME=matthew@cerberus.local,CN=USERS,CN=CERBERUS.LOCAL,CN=SYSDB
name=matthew@cerberus.local,cn=users,cn=cerberus.local,cn=sysdb
createTimestamp
1677672476
gidNumber
1000
name
matthew@cerberus.local
objectCategory
user
uidNumber
1000
isPosix
TRUE
lastUpdate
1677672476
dataExpireTimestamp
initgrExpireTimestamp
cachedPassword
$6$6LP9gyiXJCovapcy$0qmZTTjp9f2A0e7n4xk0L6ZoeKhhaCNm0VGJnX/Mu608QkliMpIy1FwKZlyUJAZU3FZ3.GQ.4N6bb9pxE3t3T0
cachedPasswordType
lastCachedPasswordChange
1677672476
failedLoginAttempts
aExpireTimestamp
initgrExpireTimestamp
uidNumber
1000
```

we know for sure now that matthew is a user in the DC and we have an encrypted password so let's crack it

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/001d1486-b3d1-4990-9112-1b9325f35cf1)

now we can add `matthew:147258369` to our creds, we want to try it on the DC so we download chisel to the machine and open up a socks proxy for us to nmap scan the DC server

### User flag

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/5ab17495-72c3-4e46-a2f9-0e0bcd2c66df)

now we can config our `/etc/proxychains.conf` and move to the process. I mentioned above that our IP is `172.16.22.2` so let's scan `172.16.22.1`

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/6224e822-517a-4205-9840-1b494009071d)

the only port I found was the winrm port so we might try the creds using `proxychains evil-winrm`

#### Important NOTE

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/0c424544-69e2-4003-8678-976e978aafdd)

This tip from 0xdf writeup on `tentacle` really saved the day as I was struggling to make nmap work with proxychains


now we can connect to the winrm port with the credentials we just accquired

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/a297b13f-c896-4a69-869f-bdc4c93fff31)

and like that we have the user.txt flag

## Privilege Escalation
I downloaded winpeas to the machine and started analyzing the output

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/5666d66e-0ef1-4acc-995f-ea48073ab636)

this binary was what caught my attention, so I went to search for it 

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/4a3d08fe-f8e4-4063-b2fa-73697fe609d8)

sounds cool but can we exploit that? yes, we can try `CVE-2022-47966` which can give us a command execution by crafting a `samlResponse` XML to the ADSelfService Plus SAML endpoint. you can read [This](https://attackerkb.com/topics/gvs0Gv8BID/cve-2022-47966/rapid7-analysis) blog for more info.
I also found [This](https://github.com/horizon3ai/CVE-2022-47966) script for the exploit but we need two things, the issuer url and the GUID which we can get from the web app, but first, we need to access the DC web server first, and since the container itself only has access to the winrm port, we will have to chain two proxies and consider the linux container as `Jump Server`, [This](https://theyhack.me/Proxychains-Double-Pivoting/) link was very helpful throughout the process.
first, we compile chisel for Windows using this command `GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" .` and then upload it to the DC

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/b31a6a4a-ca94-4c1f-acba-97f707c67b18)

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/029db6f9-e101-48c8-9ebd-79db900d3dce)

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/0611a228-9b72-4475-a8d4-b00810dcbb84)


### Root flag
since we need SAML data from the requests we can install SAML-tracer extension run `proxychains firefox https://dc.cerberus.local:9521` since it's the default port for ADSelfService Plus

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/38f931ce-9ceb-4671-aae9-221eee59edbe)

It redirects us to a login portal, let's try matthew credentials

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/2a2efd05-8cd5-4a46-aff0-6e9ea9237243)

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/6521275c-2e79-48a7-82f0-8122d11a22d3)

we got the GUID in the url but what about the issuer? if we open the SAML-tracer and analyzed the responses

![Screenshot 2023-07-28 181228](https://github.com/0xRyies/HTB_Active/assets/60355031/7d7a4659-d2e4-4f70-9de6-ce892d30cf8d)

we can clearly see the issuer, and now we can execute the script, but first I uploaded the nc binary to the DC server.
for some reason the python script so I moved to Metasploit >_<

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/05fb1e80-ccf9-40fa-9d6c-6726ce1bdcff)

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/eee68cd4-3ecd-4a0f-ac33-74fd19d9f0e4)


and we got an admin shell :D

was a really fun machine, hope you enjoyed as much as I did ._. 






















