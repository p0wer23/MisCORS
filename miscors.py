#!/usr/bin/env python3
import requests
import argparse
import os
import urllib3
import re
import concurrent.futures
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def arguments():
    #example: $ ./miscors.py -w dirs1.txt -c {session:RTddvR1IzsQGQHe2kBMyKDDXx5kgOYVH} -p "{http:http://127.0.0.1:8080,https:http://127.0.0.1:8080}"
    parser = argparse.ArgumentParser(description='''Finds CORS vulnerabilities in given website''')
    parser.add_argument('-w', '--wordlist', help='wordlist of domains to test')
    parser.add_argument('-u', '--url', help='list of URL to test')
    parser.add_argument('-c', '--cookies', help='cookies (as dict)')
    parser.add_argument('-p', '--proxy', type=str, help='Give proxy details to route the requests (as dict)')
    parser.add_argument('-t', '--threads', type=int, help='number of threads (more threads the faster;  default 1)')
    parser.add_argument('-d', '--headers', help='add custom headers (as dict)')

    args = parser.parse_args()

    if args.wordlist:
        if args.url:
            parser.error('Both -u & -w detected. Only one required.')
        elif not os.path.isfile(args.wordlist):
            parser.error(f'Wordlist \'{args.wordlist}\' does not exist')
    elif not args.url:
        parser.error('No URL input, please add -u or -w option')

    if args.proxy:
        args.proxy = args.proxy.strip()[1:-1].split(',')
        args.proxy = dict([aaa.strip().split(':',1) for aaa in args.proxy])
    if args.cookies:
        args.cookies = args.cookies.strip()[1:-1].split(',')
        args.cookies = dict([aaa.strip().split(':',1) for aaa in args.cookies])
    if args.headers:
        args.headers = args.headers.strip()[1:-1].split(',')
        args.headers = dict([aaa.strip().split(':',1) for aaa in args.headers])
    if not args.threads:
        args.threads = 5

    return args

def createOrigins(url):
    # origins = [null, random, regex, indomain, http, subdomain]
    pattern = r"(http|https):\/\/(www\.|)([^/]*)(/.*|)"
    domain = re.match(pattern, url).group(3)
    if not domain:
        print(f'Error: {url} in not in standard url form')
    origins = ['null', 'https://www.rand8f472ae1.com', f'https://rand7d44hg{domain}', f'https://{domain.split(":")[0]}.rand99dk6.com',  f'http://{re.match(pattern, url).group(2)}{domain}', f'https://rad7ee56.{domain}']
    return origins


def checkCORS(args, url):
    args.url = url
    origins = createOrigins(args.url)
    headers= {
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
        'Accept-Language': 'en-US,en;q=0.5', 
        'Origin': 'null',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'cross-site',
        'Te': 'trailers'
    }
    CORS = []
    s = requests.Session()
    if not args.cookies:
        s.get(args.url, proxies=args.proxy, verify=False)
    for i in range(len(origins)):
        headers['Origin'] = origins[i]
        if args.headers:
            headers.update(args.headers)
        res = s.get(url, headers=headers, cookies=args.cookies, proxies=args.proxy, verify=False)
        CORS.append(-1)
        if res.headers.get('Access-Control-Allow-Origin') and res.headers['Access-Control-Allow-Origin'].strip().lower() == origins[i].strip().lower():
            CORS[-1] = 0
            if res.headers['Access-Control-Allow-Credentials'] and res.headers['Access-Control-Allow-Credentials'].strip().lower()=='true':
                CORS[-1] = 1
        elif res.headers.get('Access-Control-Allow-Origin') and res.headers['Access-Control-Allow-Origin'].strip() == '*':
            CORS[-1] = 2

    return {url : CORS}

def geturls(file_name):
    urls = []
    with open(file_name, "r") as file:
        for line in file:
            urls.append(line.strip())
    return urls

def changeOutputFormat(results):
    origins = ['null', 'random', 'regex', 'indomain', 'http', 'subdomain']
    obs = {
        'null': {'ACAO & ACAC':[], 'Only ACAO':[], 'ACAO: *':[]}, 
        'random': {'ACAO & ACAC':[], 'Only ACAO':[], 'ACAO: *':[]}, 
        'regex': {'ACAO & ACAC':[], 'Only ACAO':[], 'ACAO: *':[]}, 
        'indomain': {'ACAO & ACAC':[], 'Only ACAO':[], 'ACAO: *':[]}, 
        'http': {'ACAO & ACAC':[], 'Only ACAO':[], 'ACAO: *':[]}, 
        'subdomain': {'ACAO & ACAC':[], 'Only ACAO':[], 'ACAO: *':[]}
    }
    for url in results:
        res = results[url]
        for i in range(len(origins)):
            if res[i] == 2:
                obs[origins[i]]['ACAO: *'].append(url)
            elif res[i] == 1:
                obs[origins[i]]['ACAO & ACAC'].append(url)
            elif res[i] == 0:
                obs[origins[i]]['Only ACAO'].append(url)
    return obs

def printOutput(res):
    origins_examples = ['null', 'https://www.rand8f472ae1.com', 'https://rand7d44hg{domain}', 'https://{domain}.rand99dk6.com',  'http://{url}', 'https://rad7ee56.{domain}']
    origins = ['null', 'random', 'regex', 'indomain', 'http', 'subdomain']

    for aaa in res:
        example = origins_examples[origins.index(aaa)]
        print(f'{(aaa+":").ljust(10)}\t\t (example: {example})')
        for bbb in res[aaa]:
            print(f'\t{bbb}:-')
            urls = '\n\t\t'.join(res[aaa][bbb])
            print(f'\t\t{urls}')
        print()


def main():
    args = arguments()

    if args.url:
        r = checkCORS(args, args.url)
        printOutput(changeOutputFormat(r))
    else:
        results = dict()
        urls = geturls(args.wordlist)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,args.threads)) as executor:
            r = [executor.submit(checkCORS, args, url) for url in urls]
            for f in concurrent.futures.as_completed(r):
                results.update(f.result())
            printOutput(changeOutputFormat(results))


    

if __name__=='__main__':
    main()