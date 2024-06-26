Doing a quick scan so we can be efficient with our time. We notice port 80 being open.

###### Quick scan
![[Pasted image 20230717165316.png]]
While looking at the webpage involved in this challenge, we do a full scan of every port in the background aswell as start gobuster to enumerate subdirectories.

###### Full scan
![[Pasted image 20230717170432.png]]

###### Gobuster scan
![[Pasted image 20230717172329.png]]

###### Looking at the webpage
![[Pasted image 20230717165745.png]]

We notice:
```
Flask v2.1.2
Searcher 2.4.0
```

Nothing interesting in the source.

The search function is, however, very interesting:
![[Pasted image 20230717170229.png]]
This generates an URL:
![[Pasted image 20230717170314.png]]
If we checkmark "Auto redirect" it automatically opens the link. This looks promising. Lets look at the Searcher 2.4.0.

Searchor is an all-in-one PyPi Python library that makes web scraping much easier. In the case of the webapp we are looking at, it is used to generate search query URLs like the one shown in the picture above.

When we Google the Searchor version in use, we immediately notice that the version is vulnerable to Arbitrary CMD Injection. There's a function call ``eval()``:
```Python
@click.argument("query")
def search(engine, query, open, copy):
    try:
        url = eval( # <<< See here 
            f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
        )
        click.echo(url)
        searchor.history.update(engine, query, url)
        if open:
            click.echo("opening browser...")
	  ...
```

Thanks to https://github.com/nikn0laty we can quickly spin up a reverse shell.
![[Pasted image 20230717172950.png]]
![[Pasted image 20230717173028.png]]
