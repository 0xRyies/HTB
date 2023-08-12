## Box Info

![254794672-465471f3-c924-4f57-9155-fb98a911b7ab](https://github.com/0xRyies/HTB/assets/60355031/bdf5f938-77c7-43e2-b380-ab856d13680e)

## Recon
### Nmap
nmap found two open ports 80 and 22 

![254795641-c4d04353-967b-46eb-af9c-23f634987523](https://github.com/0xRyies/HTB/assets/60355031/04363c83-ee7c-45bc-a3aa-5d71e78848e2)


it's an Ubuntu box running a web app using Python 3.10, knowing that we can move along to the actual fun

### Viewing the web app
when we visit the website it tries to connect to ```http://searcher.htb```, we can add that to our ```/etc/hosts``` and move on

![254797679-65e98ebf-2182-429b-bd1e-4d204944597f](https://github.com/0xRyies/HTB/assets/60355031/fcf5f54f-02f6-485e-8ed0-349c24abd48e)

now we are ready to play with the app, but first, we can do some basic VHost enumeration while testing since we have a hostname 

### FFUF

![254798388-a0851aed-f9d7-44ad-86e1-41b3902bfa78](https://github.com/0xRyies/HTB/assets/60355031/cf0c66b3-0ddf-4aaf-a1c3-c2cb5797249e)


we can just filter the by lines

![254841193-e930e087-4f02-45c6-b82c-c05ce9ddd05c](https://github.com/0xRyies/HTB/assets/60355031/4deb8e4b-31f4-479a-a2da-27c4df7e0cc6)


and we got one ._. , so let's add it to the ```/etc/hosts``` and view the app

playing with the search and queries we can notice something interesting 

![254799540-1104cb6a-61ff-4053-821b-58a4cd362a2c](https://github.com/0xRyies/HTB/assets/60355031/472e0b25-f86d-4771-9224-7f29691cc77e)


by following the link and looking at the latest version 

![254799906-816b0448-3704-4c42-9908-ed690e90e03d](https://github.com/0xRyies/HTB/assets/60355031/9342b469-74cd-4340-a3d0-447b512b61cc)


it looks like the web app is running an older version, we can now search for Searchor 2.4.0 exploits, the first link that comes up was this repo https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection, so let's try it out

### User Flag
running the exploit as follows and ```nc -lnvp 9001``` in another tab

![254800978-977f9f45-2c86-45de-ac4d-59ddc4d17a20](https://github.com/0xRyies/HTB/assets/60355031/05b864cb-e068-4d32-92aa-160444cd8f8d)

![254833750-32d46cc6-3079-4da9-81e8-a0a2b85dc270](https://github.com/0xRyies/HTB/assets/60355031/9d9a1daa-1058-4c99-9c6e-b16f69c6f8ba)


and voila we got a shell!

we can quickly fix our shell using ```stty raw -echo``` for a more stable one and ```python3 -c "import pty;pty.spawn('/bin/bash')"``` to make it interactive

![254834090-2158b423-0d69-48cb-b0c8-b2a1b3866430](https://github.com/0xRyies/HTB/assets/60355031/a108ddff-544a-4d6f-974a-e68b73156886)


and we can simply access user.txt 

## Privilege Escalation

![254835161-100b632b-38c9-4857-9859-eda06b455323](https://github.com/0xRyies/HTB/assets/60355031/55d9c676-b9ea-4b19-bbe3-a1352994a5ae)


when we try ```sudo -l``` it asks for a password so we can search for one.
after searching the web app for a config file, we found the .git containing his creds to the ```gitea.searcher.htb``` we found earlier

![254835940-fb28d5ba-9252-469a-9daf-c69921a07582](https://github.com/0xRyies/HTB/assets/60355031/5a4cb13b-323c-4dbb-b14d-be4c1b33a343)


and now we can peacefully login with ssh to the svc user and run ```sudo -l``` again

![254836422-7556ba37-c4b6-4c8b-8433-09694143ff46](https://github.com/0xRyies/HTB/assets/60355031/8b819a08-d3a6-4292-be03-f0bde617fe60)


we can run a script as root, sounds interesting

![254836771-45da064c-6f4e-456c-8ce0-64d75ff8ccef](https://github.com/0xRyies/HTB/assets/60355031/c8f44cca-31df-4fe5-9ff6-9c112c802f2d)


looks like the script has something to do with docker, and by playing with the commands and doing a little search I found this [blog](https://exploit-notes.hdks.org/exploit/container/docker/) containing how to use docker ps and docker inspect  

![254838068-ec006ab0-ec5e-4e00-b69d-c8ca55b80d7f](https://github.com/0xRyies/HTB/assets/60355031/456d1617-947f-4377-88b3-69a1806977e1)


and we have 2 passwords, how can we use them? let's get back to ```gitea.searcher.htb``` 

![254838383-5bf2e777-493b-433b-9ad1-aadb2600f995](https://github.com/0xRyies/HTB/assets/60355031/92c521a5-6ff5-470f-85a2-97deb48bc4b6)


let's try the 2 passwords as administrator

![254838642-bc025356-ed43-45c3-805b-4c27e927ced7](https://github.com/0xRyies/HTB/assets/60355031/73f3d0a1-e7da-4a1e-aa2d-3b77213a31b1)


one of them actually worked :D

### Root Flag

![254839040-1a68bbeb-3679-4780-b631-065ec7606f8b](https://github.com/0xRyies/HTB/assets/60355031/1040e1a6-71e7-4eb2-9c09-284b2bca7fc2)


after checking the admin repo we can find what we are looking for, the source code for the script we can run as root :D, so we move ahead and review the code, we can immediately see something interesting

![254839156-bc9a1b1a-9c56-4617-8685-7a72d0080f61](https://github.com/0xRyies/HTB/assets/60355031/c130cd22-ac63-4923-ab6d-9e657b27fa53)


the script is running any file named full-checkup.sh without specifying an absloute path, so what if we made a file with the same name containing a reverse shell ? let's try!

![254839614-55beefd5-4c2a-4324-9373-8ee090448fc4](https://github.com/0xRyies/HTB/assets/60355031/f62592a2-e7a8-43eb-92a8-3c62f43a3b25)


for some reason when i made a file containing only a bash reverse shell it gave me an error so i copied the code from gitea and added the reverse shell code at the end

![254839741-6ca32db9-a86d-45ca-a415-36813f4b2c6f](https://github.com/0xRyies/HTB/assets/60355031/fbdd33f1-e8f7-4fb0-976f-6bead2241e3d)

and we have a shell as root :D

and that's it for the machine, hope you enjoyed as much as I did ._.






