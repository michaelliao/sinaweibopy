# snspy 

SNSPY is a stand-alone Python script which provides

* OAuth2.0 authentication
* API calling wrapper

for any social network providers.

http://michaelliao.github.com/sinaweibopy/

Developed and mantained by Michael Liao. Please feel free to report bugs and
your suggestions at [here](https://github.com/michaelliao/sinaweibopy).

## OAuth2.0

OAuth 2 is a protocol focuses on client developer simplicity while providing 
specific authorization flows for web applications.

There are many social networks provides OAuth 2 authentication and APIs, and 
snspy is a simple API wrapper for any social network such as Twitter, Facebook, 
LinkedIn, Sina Weibo, etc.

snspy provides a unique API interface for developers and difference of each 
social network APIs are handled by its `mixin`.

## Basic Usage

You need to register your OAuth 2 application on the social network you choose:

[Tweeter]()
[Facebook]()
[LinkedIn]()
[Sina Weibo]()
[QQ Connect]()

After setting up your account and registering for an application, you will receive 
`YOUR_APP_KEY` and `YOUR_APP_SECRET`. Together with `YOUR_CALLBACK_URL`, these are 
the environment variables required by snspy. And you can create the APIClient now:

```python
from snspy import APIClient
from snspy import TwitterMixin      # suppose you are using Twitter

APP_KEY = 'YOUR_APP_KEY'            # app key
APP_SECRET = 'YOUR_APP_SECRET'      # app secret
CALLBACK_URL = 'YOUR_CALLBACK_URL'  # callback url

client = APIClient(TwitterMixin, app_key=APP_KEY, app_secret=APP_SECRET, redirect_uri=CALLBACK_URL)
```

Put on your website a link which redirect the user to the following
authorization URL:

```python
url = client.get_authorize_url()    # redirect the user to 'url'
```

After granting the privileges, the user will be redirected to
`YOUR_CALLBACK_URL`, with parameter `code=SOME_CODE` attached. Then you need to
get the access token using this `SOME_CODE`.

```python
r = client.request_access_token(SOME_CODE)
access_token = r.access_token  # access token，e.g., abc123xyz456
expires = r.expires      # token expires time, UNIX timestamp, e.g., 1384826449.252 (10:01 am, 19 Nov 2013, UTC+8:00)
NOTE: you should store the access_token for later use.
```

After got access token you can init the APIClient any time:

```python
client = APIClient(TwitterMixin,
                   app_key=APP_KEY, app_secret=APP_SECRET, redirect_uri=CALLBACK_URL,
                   access_token=YOUR_ACCESS_TOKEN, expires=EXPIRES_TIME)
```

Then, you are free to call whatever API you like. For example,

```python
print client.statuses.user_timeline.get()
print client.statuses.update.post(status=u'test plain weibo')
print client.statuses.upload.post(status=u'test weibo with picture',
                                  pic=open('/Users/michael/test.png'))
```

## How to call a particular API

Firstly, refer to the corresponding API document. Use
[`user_timeline`](http://open.weibo.com/wiki/2/statuses/user_timeline/en) as an
example:

```
API:
statuses/user_timeline

HTTP Request Method:
GET

Request Parameters:
source:       string, This parameter is not needed when using OAuth. The value
                      of this parameter is the AppKey.
access_token: string, This parameter is required when using OAuth.You will get
                      the access_token after oauth authorization. 
uid:          int64,  Return the weibos of specified ID of a user. 
screen_name:  string, The nickname of the user that ID is specified. 
```

Substitute `/` in the API with `.`, and call `get()` or `post()` according to
the request method with all the necessary parameters excluding `source` and
`access_token`.

```python
r = client.statuses.user_timeline.get(uid=SOME_ID)
for st in r.statuses:
    print st.text
```

If the request method is `POST`, then it should be something like the following:

```python
r = client.statuses.update.post(status=u'test weibo')
```

And, as for uploading pictures:

```python
f = open('/Users/michael/test.png', 'rb')
r = client.statuses.upload.post(status=u'test weibo with picture', pic=f)
f.close()  # you need to do this manually
```

Please notice that what is uploaded must be a file-like object. str can be
wrapped using `StringIO`.

## wiki

For more information, please refer to
[the wiki](https://github.com/michaelliao/sinaweibopy/wiki/OAuth2-HOWTO).
