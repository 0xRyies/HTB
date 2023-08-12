## Box Info
![0_UXHLp-YKsVAiFidx](https://github.com/0xRyies/HTB_Active/assets/60355031/465471f3-c924-4f57-9155-fb98a911b7ab)

## Recon
### Nmap
nmap found two open ports 80 and 22 

![Nmap_scan](https://github.com/0xRyies/HTB_Active/assets/60355031/c4d04353-967b-46eb-af9c-23f634987523)

it's an Ubuntu box running a web app using Python 3.10, knowing that we can move along to the actual fun

### Viewing the web app
when we visit the website it tries to connect to ```http://searcher.htb```, we can add that to our ```/etc/hosts``` and move on

![the website](https://github.com/0xRyies/HTB_Active/assets/60355031/65e98ebf-2182-429b-bd1e-4d204944597f)

now we are ready to play with the app, but first, we can do some basic VHost enumeration while testing since we have a hostname 

### FFUF
![ffuf_vhosts](https://github.com/0xRyies/HTB_Active/assets/60355031/a0851aed-f9d7-44ad-86e1-41b3902bfa78)

we can just filter the by lines

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/e930e087-4f02-45c6-b82c-c05ce9ddd05c)

and we got one ._. , so let's add it to the ```/etc/hosts``` and view the app

playing with the search and queries we can notice something interesting 

![Screenshot 2023-07-20 095918](https://github.com/0xRyies/HTB_Active/assets/60355031/1104cb6a-61ff-4053-821b-58a4cd362a2c)

by following the link and looking at the latest version 

![searchor_engine_github](https://github.com/0xRyies/HTB_Active/assets/60355031/816b0448-3704-4c42-9908-ed690e90e03d)

it looks like the web app is running an older version, we can now search for Searchor 2.4.0 exploits, the first link that comes up was this repo https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection, so let's try it out

### User Flag
running the exploit as follows and ```nc -lnvp 9001``` in another tab

![exploit_cve](https://github.com/0xRyies/HTB_Active/assets/60355031/977f9f45-2c86-45de-ac4d-59ddc4d17a20)

![shell1](https://github.com/0xRyies/HTB_Active/assets/60355031/32d46cc6-3079-4da9-81e8-a0a2b85dc270)
and voila we got a shell!

we can quickly fix our shell using ```stty raw -echo``` for a more stable one and ```python3 -c "import pty;pty.spawn('/bin/bash')"``` to make it interactive

![user_flag](https://github.com/0xRyies/HTB_Active/assets/60355031/2158b423-0d69-48cb-b0c8-b2a1b3866430)

and we can simply access user.txt 

## Privilege Escalation

![Screenshot 2023-07-20 121010](https://github.com/0xRyies/HTB_Active/assets/60355031/100b632b-38c9-4857-9859-eda06b455323)

when we try ```sudo -l``` it asks for a password so we can search for one.
after searching the web app for a config file, we found the .git containing his creds to the ```gitea.searcher.htb``` we found earlier

![getting_user_password](https://github.com/0xRyies/HTB_Active/assets/60355031/fb28d5ba-9252-469a-9daf-c69921a07582)

and now we can peacfully login with ssh to the svc user and run ```sudo -l``` again

![sudo-l](https://github.com/0xRyies/HTB_Active/assets/60355031/7556ba37-c4b6-4c8b-8433-09694143ff46)

we can run a script as root, sounds interesting
![sudoCommand](https://github.com/0xRyies/HTB_Active/assets/60355031/45da064c-6f4e-456c-8ce0-64d75ff8ccef)


looks like the script has something to do with docker, and by playing with the commands and doing a little search I found this [blog](https://exploit-notes.hdks.org/exploit/container/docker/) containing how to use docker ps and docker inspect  

![getting_mysql_root_creds](https://github.com/0xRyies/HTB_Active/assets/60355031/ec006ab0-ec5e-4e00-b69d-c8ca55b80d7f)

and we have 2 passwords, how can we use them? let's get back to ```gitea.searcher.htb``` 

![Screenshot 2023-07-20 122207](https://github.com/0xRyies/HTB_Active/assets/60355031/5bf2e777-493b-433b-9ad1-aadb2600f995)

let's try the 2 passwords as administrator

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/bc025356-ed43-45c3-805b-4c27e927ced7)

one of them actually worked :D

### Root Flag

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/1a68bbeb-3679-4780-b631-065ec7606f8b)

after checking the admin repo we can find what we are looking for, the source code for the script we can run as root :D, so we move ahead and review the code, we can immediately see something interesting

![vulnerable_code_to_root](https://github.com/0xRyies/HTB_Active/assets/60355031/bc9a1b1a-9c56-4617-8685-7a72d0080f61)

the script is running any file named full-checkup.sh without specifying an absloute path, so what if we made a file with the same name containing a reverse shell ? let's try!

![image](https://github.com/0xRyies/HTB_Active/assets/60355031/55beefd5-4c2a-4324-9373-8ee090448fc4)

for some reason when i made a file containing only a bash reverse shell it gave me an error so i copied the code from gitea and added the reverse shell code at the end

![root_shell](https://github.com/0xRyies/HTB_Active/assets/60355031/6ca32db9-a86d-45ca-a415-36813f4b2c6f)

and we have a shell as root :D

and that's it for the machine, hope you enjoyed as much as I did ._.






