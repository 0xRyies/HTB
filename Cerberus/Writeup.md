## Box Info

![256833222-42b999fe-8f77-423b-81c0-bc73bd1e63ef](https://github.com/0xRyies/HTB/assets/60355031/3b520c60-e6b7-487c-adb7-0ed193bcde37)


## Recon 
### Nmap
![256833821-c69f8bf8-fe29-4876-9d45-833662613214](https://github.com/0xRyies/HTB/assets/60355031/44f70171-65a6-4e86-b230-5c854e8d0ba4)

Nmap found one open port `8080` running `Apache 2.4.52` and it's redirecting to `icinga.cerberus.local `, so let's add that to our `/etc/hosts` and view the web app

### Viewing the web app

![256834879-18dc3b2f-8042-414b-97a2-a1113ab2ca54](https://github.com/0xRyies/HTB/assets/60355031/f1df3664-f93c-40e8-91d1-6fa4799d18b3)


we can search for `IcingaWeb 2` vulnerabilities

![256835539-f3c16f14-02e2-4549-9c38-c9a310c0981f](https://github.com/0xRyies/HTB/assets/60355031/e7090fb5-162d-4f9d-8b70-3331780bba25)


there's a file disclosure vulnerability with the `CVE-2022-24716`, so let's try it out!

![256836109-a0390583-5e5d-4a37-8cc6-f85cffdc9a8d](https://github.com/0xRyies/HTB/assets/60355031/b4e4968c-79e8-463f-a0c1-5eddd833dbf1)


and it's working, but what can we do with it? I tried searching for IcingaWeb 2 default config file locations and found [This](https://wiki.archlinux.org/title/Icinga) article, I checked these files but the most important one was the `resources.ini`

![256836947-03537395-de8e-437a-888f-2eff6b514d9b](https://github.com/0xRyies/HTB/assets/60355031/dd52ffe7-5b5e-4ba7-8b79-5855c5c2c463)


It had `matthew` password, so let's try this out on the login portal 

![256837271-5da4f310-a195-4c56-847c-a4f9b7184a57](https://github.com/0xRyies/HTB/assets/60355031/686f7067-d170-4b3e-92df-62baf6e51556)


and we are in! after playing around with the dashboard I found nothing really useful except for this password 

![256837705-861465d2-7cf2-46c2-bae2-5d5bc777c500](https://github.com/0xRyies/HTB/assets/60355031/a990477e-962d-4c83-ab60-0dcc057b43b0)


but that wasn't very handy, so I tried searching for an authenticated vulnerability, and found [This](https://github.com/JacobEbben/CVE-2022-24715) repo that had a PoC for `CVE-2022-24715` that allows an authenticated user for an RCE, let's try it

![256839211-2004aa10-cdd2-4de0-b5ca-5081e47a6ecf](https://github.com/0xRyies/HTB/assets/60355031/c87f4974-7dd0-41b5-8da9-a743cf15c325)


and we have a shell as `www-data`, we can upgrade our shell using `python3 -c 'import pty;pty.spawn("/bin/bash")'` and move on. 

if we tried `ifconfig`

![256849005-fd6c79ad-ae2c-4d6e-9cad-491a8fced4ae](https://github.com/0xRyies/HTB/assets/60355031/48d836c6-0cb5-49aa-960a-b8320145b116)


looks like we are in a type of sandboxed environment with the IP `172.16.22.2` , after playing around the machine I ended up running linpeas and found that we are in a `firejail` sandbox, so we can check for the version

![256841123-d0ea7153-2715-440a-bdf2-6fb821a8679a](https://github.com/0xRyies/HTB/assets/60355031/22394864-296b-40f1-bfb6-2a66c87d31eb)


and that's actually vulnerable to `CVE-2022-31214` that allows us to get a root shell!

![256842164-36b61dd6-e383-49c1-8f67-ec45f5e7f088](https://github.com/0xRyies/HTB/assets/60355031/26e66f98-c6f5-4626-b01e-ca57e34ea4e2)


since we are now root, we can play around more, while hanging around in the /etc/ directory I found something called sssd which was weird enough for me to look at

![256843054-c995f86a-43f0-4c5b-be43-d636c62511fc](https://github.com/0xRyies/HTB/assets/60355031/41faca62-0da1-4d2f-99ba-f4d980f6ff56)


`SSSD is a system daemon. Its primary function is to provide access to local or remote identity and authentication resources through a common framework that can provide caching and offline support to the system.`
so this might be useful! I quickly searched for Linux active directory pentest and found this on [hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-active-directory)  

![256845136-84754748-a1c9-4f2a-97c0-2a0f27cdfc34](https://github.com/0xRyies/HTB/assets/60355031/c914d641-3fc8-4090-9964-1857b0d9337d)

![256845796-9b663ef0-3f01-41ca-b1f2-3d0dea2caf0d](https://github.com/0xRyies/HTB/assets/60355031/9b900290-f841-46a9-a7f0-bc9a5dbacf29)


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

![256847039-001d1486-b3d1-4990-9112-1b9325f35cf1](https://github.com/0xRyies/HTB/assets/60355031/9400fc9e-8ffb-489e-b7a1-ba6d7d346f11)


now we can add `matthew:147258369` to our creds, we want to try it on the DC so we download chisel to the machine and open up a socks proxy for us to nmap scan the DC server

### User flag

![256848603-5ab17495-72c3-4e46-a2f9-0e0bcd2c66df](https://github.com/0xRyies/HTB/assets/60355031/29b01bcd-13ad-47af-b0ed-8a622b9dd6ad)


now we can config our `/etc/proxychains.conf` and move to the process. I mentioned above that our IP is `172.16.22.2` so let's scan `172.16.22.1`

![256861560-6224e822-517a-4205-9840-1b494009071d](https://github.com/0xRyies/HTB/assets/60355031/095114dd-c3b5-4d41-95d7-51783fc3e06a)


the only port I found was the winrm port so we might try the creds using `proxychains evil-winrm`

#### Important NOTE

![256850564-0c424544-69e2-4003-8678-976e978aafdd](https://github.com/0xRyies/HTB/assets/60355031/e0eb90a1-a488-4de1-8db9-af5fd32f7bc1)


This tip from 0xdf writeup on `tentacle` really saved the day as I was struggling to make nmap work with proxychains


now we can connect to the winrm port with the credentials we just accquired

![256851475-a297b13f-c896-4a69-869f-bdc4c93fff31](https://github.com/0xRyies/HTB/assets/60355031/ad17e5b4-9ba6-412f-a039-e1f4d9b11d55)


and like that we have the user.txt flag

## Privilege Escalation
I downloaded winpeas to the machine and started analyzing the output

![256852030-5666d66e-0ef1-4acc-995f-ea48073ab636](https://github.com/0xRyies/HTB/assets/60355031/5e761186-c9f3-49b1-95bd-82276b5b0047)


this binary was what caught my attention, so I went to search for it 

![256852353-4a3d08fe-f8e4-4063-b2fa-73697fe609d8](https://github.com/0xRyies/HTB/assets/60355031/d3dac51c-d41b-4a96-885c-fa0f582cb055)


sounds cool but can we exploit that? yes, we can try `CVE-2022-47966` which can give us a command execution by crafting a `samlResponse` XML to the ADSelfService Plus SAML endpoint. you can read [This](https://attackerkb.com/topics/gvs0Gv8BID/cve-2022-47966/rapid7-analysis) blog for more info.
I also found [This](https://github.com/horizon3ai/CVE-2022-47966) script for the exploit but we need two things, the issuer url and the GUID which we can get from the web app, but first, we need to access the DC web server first, and since the container itself only has access to the winrm port, we will have to chain two proxies and consider the linux container as `Jump Server`, [This](https://theyhack.me/Proxychains-Double-Pivoting/) link was very helpful throughout the process.
first, we compile chisel for Windows using this command `GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" .` and then upload it to the DC

![256858335-b31a6a4a-ca94-4c1f-acba-97f707c67b18](https://github.com/0xRyies/HTB/assets/60355031/ac817de6-926b-4418-b527-caa29c755e6d)

![256858382-029db6f9-e101-48c8-9ebd-79db900d3dce](https://github.com/0xRyies/HTB/assets/60355031/e1e47f16-c85a-4656-bea2-1f26c7a680d1)

![256859137-0611a228-9b72-4475-a8d4-b00810dcbb84](https://github.com/0xRyies/HTB/assets/60355031/bf937a97-22d6-4786-84c3-7ff5d839d409)



### Root flag
since we need SAML data from the requests we can install SAML-tracer extension run `proxychains firefox https://dc.cerberus.local:9521` since it's the default port for ADSelfService Plus

![256859845-38f931ce-9ceb-4671-aae9-221eee59edbe](https://github.com/0xRyies/HTB/assets/60355031/05767e4c-e9dd-4002-b564-8580524c603e)


It redirects us to a login portal, let's try matthew credentials

![256860518-2a2efd05-8cd5-4a46-aff0-6e9ea9237243](https://github.com/0xRyies/HTB/assets/60355031/54b0a3d6-c5a8-4b6f-ba78-c59c726c349a)

![256860700-6521275c-2e79-48a7-82f0-8122d11a22d3](https://github.com/0xRyies/HTB/assets/60355031/d9bd4c4b-fb47-49e4-8189-9ff15bfcfd23)



we got the GUID in the url but what about the issuer? if we open the SAML-tracer and analyzed the responses

![256861037-7d7a4659-d2e4-4f70-9de6-ce892d30cf8d](https://github.com/0xRyies/HTB/assets/60355031/6273e4f9-fe0a-4b43-a597-0a5f7fc0b885)


we can clearly see the issuer, and now we can execute the script, but first I uploaded the nc binary to the DC server.
for some reason the python script so I moved to Metasploit >_<

![256869853-05fb1e80-ccf9-40fa-9d6c-6726ce1bdcff](https://github.com/0xRyies/HTB/assets/60355031/94f3bf30-b455-4c06-9bcf-9aaadd5b9f3e)


![256870045-eee68cd4-3ecd-4a0f-ac33-74fd19d9f0e4](https://github.com/0xRyies/HTB/assets/60355031/7705d74f-4c8a-4637-8334-4ac6108a0880)



and we got an admin shell :D

was a really fun machine, hope you enjoyed as much as I did ._. 






















