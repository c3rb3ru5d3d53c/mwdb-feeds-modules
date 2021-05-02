#!/usr/bin/env python

import re
import json
import tweepy
import logging
import hashlib
import requests

log = logging.getLogger(__name__)

__author__  = 'c3rb3ru5'
__version__ = '1.0.0'

class TwitterListener(tweepy.StreamListener):
    """
    Twitter API Listener
    """
    def __init__(self, api, mwdb, config):
        self.name       = 'twitter'
        self.tag        = f'feed:{self.name}'
        self.api        = api
        self.mwdb       = mwdb
        self.config     = config
        self.regMD5     = re.compile(r'(?:[^a-fA-F\d]|\b)([a-fA-F\d]{32})(?:[^a-fA-F\d]|\b)')
        self.regSHA1    = re.compile(r'(?:[^a-fA-F\d]|\b)([a-fA-F\d]{40})(?:[^a-fA-F\d]|\b)')
        self.regSHA256  = re.compile(r'(?:[^a-fA-F\d]|\b)([a-fA-F\d]{64})(?:[^a-fA-F\d]|\b)')
        self.vt_url     = 'https://virustotal.com/api/v3'
        self.vt_headers = {
            'x-apikey': self.config.get(self.name, 'vt_api_key'),
            'User-Agent': f'mwdb-feeds/{__version__}'
        }
        self.verify_ssl = self.config.getboolean(self.name, 'verify_ssl')

    @staticmethod
    def tweet_get_tags(tweet):
        tags = []
        for tag in tweet.entities.get('hashtags'):
            tags.append(tag['text'])
        return list(set(tags))

    def get_hashes(self, text):
        hashes = []
        hashes.extend(re.findall(self.regMD5, text))
        hashes.extend(re.findall(self.regSHA1, text))
        hashes.extend(re.findall(self.regSHA256, text))
        return list(filter(None, hashes))

    def vt_search(self, file_hash):
        url = self.vt_url + f'/search?query={file_hash}'
        r = requests.get(url=url, headers=self.vt_headers, verify=self.verify_ssl)
        if r.status_code == 200 and len(r.json()['data']) > 0:
            return r.json()['data'][0]['attributes']['last_analysis_stats']['malicious']
        return 0

    def vt_download(self, file_hash):
        url = self.vt_url + f'/files/{file_hash}/download'
        r = requests.get(url=url, headers=self.vt_headers, allow_redirects=True, verify=self.verify_ssl)
        if r.status_code == 200:
            return r.content
        return None

    def mwdb_upload(self, file_hash, url):
        if self.vt_search(file_hash) >= self.config.getint(self.name, 'threshold'):
            if self.mwdb.query_file(file_hash, raise_not_found=False) is None:
                log.debug(f'downloading {file_hash}')
                data = self.vt_download(file_hash)
                if data is not None:
                    log.debug(f'uploading {file_hash} to mwdb')
                    result = self.mwdb.upload_file(name=file_hash, content=data)
                    result.add_tag(self.tag)
                    result.add_metakey(self.name, url)
                    log.debug(f'uploaded {file_hash} to mwdb')

    def on_status(self, tweet):
        if not hasattr(tweet, 'retweeted_status') or self.config.getboolean(self.name, 'retweets') is True:
            tweet = self.api.get_status(tweet.id_str, tweet_mode='extended')
            tweet = {
                'id': tweet.id_str,
                'url': f'https://twitter.com/user/status/{tweet.id_str}',
                'user': tweet.user.screen_name,
                'tags': self.tweet_get_tags(tweet),
                'text': tweet.full_text,
                'hashes': self.get_hashes(tweet.full_text)
            }
            for file_hash in tweet['hashes']:
                self.mwdb_upload(file_hash, tweet['url'])
            if len(tweet['hashes']) > 0:
                print(json.dumps(tweet, indent=4))

class MWDBFeedsModule():

    """
    A Twitter Bot MWDB Sample Collector Module
    """

    def __init__(self, config, mwdb):
        self.name = 'twitter'
        self.tag = f'feed:{self.name}'
        self.enabled = self.startup(config)
        self.mwdb = mwdb

    def startup(self, config):
        options = [
            'consumer_key',
            'consumer_secret',
            'access_token',
            'access_token_secret',
            'enabled',
            'threshold',
            'usernames',
            'hashtags',
            'vt_api_key',
            'stream',
            'tweets_max',
            'retweets']
        for option in options:
            if config.has_option(self.name, option) is False:
                log.warning(f'{self.name} section is missing the {option} option')
                return False
        self.config = config
        return self.config.getboolean(self.name, 'enabled')

    def twitter_login(self):
        self.auth =  tweepy.OAuthHandler(
            self.config.get(self.name, 'consumer_key'),
            self.config.get(self.name, 'consumer_secret'))
        self.auth.set_access_token(
            self.config.get(self.name, 'access_token'),
            self.config.get(self.name, 'access_token_secret'))
        self.api = tweepy.API(self.auth)

    def get_uids(self):
        ids = []
        for username in self.get_config_list('usernames'):
            ids.append(str(self.api.get_user(screen_name=username).id))
        return list(set(ids))

    def get_config_list(self, option):
        return self.config.get(self.name, option).split(',')

    def main(self) -> dict:
        result = {
            'module': self.name,
            'success': True
        }
        try:
            self.twitter_login()
            if self.config.getboolean(self.name, 'stream') is True:
                listener = TwitterListener(api=self.api, mwdb=self.mwdb, config=self.config)
                stream = tweepy.Stream(self.auth, listener)
                stream.filter(
                    track=self.get_config_list('hashtags'),
                    follow=self.get_uids())
            print("Hello World!")
        except Exception as error:
            log.error(error)
            result['success'] = False
        return result
