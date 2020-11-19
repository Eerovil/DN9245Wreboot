
import sys
import hashlib
import re
import base64
import json
from time import sleep
import requests
from config import ROUTER, USER, PASSWORD


def setup_session(client, server):
    """ gets the url from the server ignoring the respone, just to get session cookie set up """
    url = "http://%s/html/index.html" % server
    response = client.get(url)
    response.raise_for_status()
    sleep(1)
    csrf_param = re.search(r'<meta name="csrf_param" content="(\w+)"', response.content).groups()[0]
    csrf_token = re.search(r'<meta name="csrf_token" content="(\w+)"', response.content).groups()[0]
    chap_challenge = re.search(r'<meta name="chap_challenge" content="(\w+)"', response.content).groups()[0]
    return csrf_param, csrf_token, chap_challenge

def login(client, server, user, password, headers):
    """ logs in to the router """
    csrf_param, csrf_token, chap_challenge = setup_session(client, server)

    data = {
        'csrf': {
            'csrf_param': csrf_param,
            'csrf_token': csrf_token,
        },
        'data': {
            'LoginFlag': 1,
            'UserName': user,
        }
    }

    url = "http://%s/api/system/user_login" % server

    sha256password = hashlib.sha256()
    sha256password.update(password)
    b64sha256password = base64.b64encode(sha256password.hexdigest())

    variable_f = hashlib.sha256()
    variable_f.update(user)
    variable_f.update(b64sha256password)
    variable_f.update(csrf_param)
    variable_f.update(csrf_token)
    data['data']['Password'] = variable_f.hexdigest()


    data['data']['challenge'] = chap_challenge

    variable_j = hashlib.sha256()
    variable_j.update("{}:{}".format(data['data']['challenge'], data['data']['Password']))
    data['data']['Password'] = variable_j.hexdigest()

    resp = client.post(url, json.dumps(data), headers=headers)
    response = client.get("http://{}/html/advance.html".format(server))
    csrf_param = re.search(r'<meta name="csrf_param" content="(\w+)"', response.content).groups()[0]
    csrf_token = re.search(r'<meta name="csrf_token" content="(\w+)"', response.content).groups()[0]
    return csrf_param, csrf_token


def reboot(client, server, user, password):
    """ reboots the router :) """
    headers = {linearr[0].strip(): linearr[1].strip() for linearr in  [line.strip().split(":") for line in 
    """Accept: application/json, text/javascript, */*; q=0.01
        Accept-Encoding: gzip, deflate
        Accept-Language: en-US,en;q=0.9,fi;q=0.8
        Cache-Control: no-cache
        Connection: keep-alive
        Content-Type: application/json;charset=UTF-8
        DNT: 1
        Host: {server}
        Origin: http://{server}
        Pragma: no-cache
        Referer: http://{server}/html/index.html
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36
        X-Requested-With: XMLHttpRequest""".format(server=server).split("\n")]
    }
    csrf_param, csrf_token = login(client, server, user, password, headers)

    data = {
        'csrf': {
            'csrf_param': csrf_param,
            'csrf_token': csrf_token,
        },
    }
    resp = client.post(
        "http://{}/api/service/reboot.cgi".format(server),
        json.dumps(data), headers=headers
    )


def main():
    """ main method """
    client = requests.Session()
    reboot(client, ROUTER, USER, PASSWORD)


if __name__ == "__main__":
    sys.exit(main())
