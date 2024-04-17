# MisCORS
python script to find CORS misconfigurations

## 

    usage: $ miscors.py [-h] [-w WORDLIST] [-u URL] [-c COOKIES] [-p PROXY] [-d HEADERS]
    example:  $ ./miscors.py -w dirs1.txt -c {session:2CcUpAZ2i2tNBIayEBFD8vHmInFb3rWs} -p "{http:http://127.0.0.1:8080,https:http://127.0.0.1:8080}"



options:

      -h, --help            show this help message and exit
      
      -w WORDLIST, --wordlist WORDLIST
                        wordlist of domains to test
      -u URL, --url URL     list of URL to test
      -c COOKIES, --cookies COOKIES
                        cookies (as dict)
      -p PROXY, --proxy PROXY
                        Give proxy details to route the requests (as dict)
      -d HEADERS, --headers HEADERS
                        add custom headers (as dict)

