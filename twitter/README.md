# MWDB Feeds Twitter Bot

A MWDB Feeds module and Twitter bot that downloads malicious VirusTotal samples and uploads them to MWDB

**Configuration:**
```ini
[twitter]
enabled = True
consumer_key = <your-consumer-key>
consumer_secret = <your-consumer-secret>
access_token = <your-access-token>
access_token_secret = <your-token-secret>
threshold = 4
usernames = <list-of-usernames-to-follow-comma-delimited>
hashtags = <hashtags-to-follow-comma-delimited>
vt_api_key = <your-virustotal-api-key>
stream = False
tweets_max = 10
retweets = True
verify_ssl = False
```

**Additional Resources:**
- [`Create Twitter Tokens`](https://developer.twitter.com/apps)
- [`Getting a VirusTotal API Key`](https://developers.virustotal.com/v3.0/reference#getting-started)
- [`Tweepy Documentation`](https://docs.tweepy.org/en/latest/)
