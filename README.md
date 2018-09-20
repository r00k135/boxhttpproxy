# boxhttpproxy
Proxy Box.com online storage to a local network and translate from HTTPS to HTTP - I originally wrote it so that I could serve my home media collection from Box.com via Kodi and using a simple and low cost piece of hardware such as a raspberry pi seemed like a good approach.

1. [ Install. ](#install)
2. [ Get API Information. ](#getapi)
3. [ Run. ](#run)
4. [ References. ](#ref)

<a name="install"></a>
## Install
Install python3 and dependent modules:

```sh
sudo apt-get install python3 python3-pip
pip3 install "boxsdk>=1.5,<2.0"
```

Clone this repo:
```sh
git clone <this repo>
```

<a name="getapi"></a>
### Get API Information (I have already done this and hard-coded the App details)
Access Box Developer Portal and Create a new Custom App and use Standard Oauth 2.0: https://developer.box.com/docs/setting-up-an-oauth-app
Provides a "Client ID" and "Client Secret"

<a name="run"></a>
## Run (as non-root user)

```sh
./boxhttpserver.py <port number - optional, default is 8080>
```

First time you fun this will prompt you to log-in to box and ask you to authorise the app. This runs in the foreground so when you exit the process it unmounts the filesystem. To exit press CTRL-C and then it exits into an interactive python prompt, the press CTRL-D to exit completely.

<a name="ref"></a>
## References

> Urllib3: https://github.com/urllib3/urllib3
> Box Python SDK: https://github.com/box/box-python-sdk
> Box Python SDK Intro: http://opensource.box.com/box-python-sdk/tutorials/intro.html
> Box API: https://developer.box.com/v2.0/reference


