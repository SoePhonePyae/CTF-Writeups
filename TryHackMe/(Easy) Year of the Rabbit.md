# Year of the Rabbit 
# Easy

Before we start doing anything, I'm gonna put this inside hosts as "rabbit.thm" so that I don't need to type numbers anymore. 

![Nmap Scan](https://github.com/SoePhonePyae/CTF-Writeups/blob/main/TryHackMe/Pics/1.rabbit_enum.png)

Nmap scan showed only 3 ports are open,21,22 and 80.
We try to login ftp anonymously but couldn't do it and we don't have the creditentials for ssh. 
So, port 80 is the only place for us to start.
I ran gobuster and only "assets" directory came up which is kinda weird...
But I followed the directory and found an interesting video together with a css file.