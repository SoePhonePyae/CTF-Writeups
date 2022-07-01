# Year of the Rabbit 
# Easy

Before we start doing anything, I'm gonna put this inside hosts as "rabbit.thm" so that I don't need to type numbers anymore. 

![Nmap Scan](https://github.com/SoePhonePyae/CTF-Writeups/blob/main/TryHackMe/Pics/1.rabbit_enum.png)

Nmap scan showed only 3 ports are open,21,22 and 80.

We try to login ftp anonymously but couldn't do it and we don't have the credentials for ssh. 

So, port 80 is the only place for us to start.

I ran gobuster and only "assets" directory came up which is kinda weird...

But I followed the directory and found an interesting video together with a css file.

![Interesting CSS](https://github.com/SoePhonePyae/CTF-Writeups/blob/main/TryHackMe/Pics/2.interestingcss.png)

There's a comment with a hint about a secret directory. Great! Let's follow that.

![TURN OFF JAVASCRIPT](https://github.com/SoePhonePyae/CTF-Writeups/blob/main/TryHackMe/Pics/3.turnoffjs.png)

Uh oh! The box wants us to turn off javascript. Ok, that's not a big deal.

I'm on Firefox so I just needed to type "about:config" in the address bar and then search javascript, disable it. Easy stuff.

But nothing useful comes up and we're now in a rabbit hole (pun intended).

And then I tried to intercept all the pages with burpsuite.

VOILA!!

![Burpsuite Intercept](https://github.com/SoePhonePyae/CTF-Writeups/blob/main/TryHackMe/Pics/4.burp_ss.png)

Another hidden directory. Let's follow that.

![Hidden Directory](https://github.com/SoePhonePyae/CTF-Writeups/blob/main/TryHackMe/Pics/5.hidden_dir.png)

A directory with a single picture... There aren't anything really interesting except this picture.

Typically in CTFs, a picture means steganography. Let's try if there really is a steganography involved. 

![NO Steganography](https://github.com/SoePhonePyae/CTF-Writeups/blob/main/TryHackMe/Pics/6.stuckhide.png)

PNG are not supported... I guess I should learn more about Steganography. 

So, this is another rabbit hole. 

Normally I'd be stuck here but my very straight habit of trying-to-strings-every-file saved me here.

![Secret Message](https://github.com/SoePhonePyae/CTF-Writeups/blob/main/TryHackMe/Pics/7.secretmsg.png)

There's a secret message at the end of that picture. Strange... I didn't know you can do that.

So, we have a username and passwords list for ftp. We can bruteforce it with hydra! (if it's not another rabbit hole of course..)

```
hydra -l ftpuser -P "password_list" ftp://rabbit.thm
```

Ok. We got the password. There's a shared text file in ftp and when we open it-

![Brainfuck](https://github.com/SoePhonePyae/CTF-Writeups/blob/main/TryHackMe/Pics/8.goodoldbrainfuck.png)

Brainfucc it is!! We could just search for an online decoder and just copy paster it. Very Easy.

![EZ Brainfuck](https://github.com/SoePhonePyae/CTF-Writeups/blob/main/TryHackMe/Pics/9.brainfuckdone.png)

We get another set of credentials. Let's try with ssh. It's about time we get a shell, right...?

![SSH](https://github.com/SoePhonePyae/CTF-Writeups/blob/main/TryHackMe/Pics/10.sshshell.png)

YAY!! It works!!.

But wait a second... where is the flag?? Let's do a quick "locate" for user.txt

![Lateral Movement](https://github.com/SoePhonePyae/CTF-Writeups/blob/main/TryHackMe/Pics/11.newuser.png)

So user flag is owned by another user called "Gwendoline".

Doesn't the name sound familiar?? Ofcourse we've seen that name since it's the name that's on the banner when we logged into SSH.

The banner mentioned about their "s3cr3t" place. Let's just copy paste that name and locate it real fast.

![User Credentials](https://github.com/SoePhonePyae/CTF-Writeups/blob/main/TryHackMe/Pics/12.lateral.png)

Aha!! We get the password for Gwendoline.

Switch user and then we got the user flag!!

So, learn your lessons my friends. Short and predictable passwords are bad. But writing passwords in plaintexts are worse!! DON'T DO THAT!!

I ran LinPeas for privilege escalation and nothing interesting shows up.

(Sure, It's vulnerable to CVE-2019-4034 but that's not our goal here...)

Since we have the password for the current user, we should run "sudo -l".

![sudo -l](https://github.com/SoePhonePyae/CTF-Writeups/blob/main/TryHackMe/Pics/13.weirdsudo.png)

Hmmm. I've never seen that kind of permission before (!root). 

We can run vim as every user but except root. That's unfortunate :(

or Is it? 

There's a CVE for this misconfiguration. Here's the link for it for further reading... 
https://github.com/kumar1100/CVE2019-14287

With that CVE and the help of gtfobins, we get a root shell now!! Yay!!

![Root Shell](https://github.com/SoePhonePyae/CTF-Writeups/blob/main/TryHackMe/Pics/14.root.png)


# Comments
  This is an interesting box for sure. Getting foothold is very CTF-y and fun but Privilege escalation is really interesting and useful.
