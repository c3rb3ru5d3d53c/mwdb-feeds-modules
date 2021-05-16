#!/usr/bin/env python

import json
import magic
import hashlib
import logging
import requests
from mwdblib import MWDB
from datetime import datetime, timedelta

requests.packages.urllib3.disable_warnings()

log = logging.getLogger(__name__)

__author__  = 'c3rb3ru5'
__version__ = '1.0.0'

class MWDBFeedsModule():

    """
    A MalShare Feeds Module for mwdb-feeds
    """

    def __init__(self, config, mwdb):
        self.name = 'malshare'
        self.tag = f'feed:{self.name}'
        self.url = 'https://malshare.com'
        self.enabled = self.startup(config)
        self.headers = {
            'User-Agent': f'mwdb-feeds-{self.name}/{__version__}'
        }
        self.verify_ssl = self.config.getboolean(self.name, 'verify_ssl')
        self.api_key = self.config.get(self.name, 'api_key')
        self.mwdb = mwdb

    def startup(self, config):
        options = ['enabled', 'api_key', 'days', 'verify_ssl']
        for option in options:
            if config.has_option(self.name, option) is False:
                log.warning(f'{self.name} section is missing the {option} option')
                return False
        self.config = config
        return self.config.getboolean(self.name, 'enabled')

    def get_hashes(self):
        log.debug('downloding hashes...')
        hashes = []
        for day in range(1, self.config.getint(self.name, 'days')+1):
            date = datetime.now() - timedelta(days=day)
            date = date.strftime("%Y-%m-%d")
            r = requests.get(
                url=self.url + f'/daily/{date}/malshare_fileList.{date}.sha256.txt',
                headers=self.headers,
                verify=self.verify_ssl
            )
            if r.status_code == 200:
                hashes.extend(r.content.decode('utf-8').splitlines())
        return list(set(hashes))

    def download(self, file_hash):
        log.debug(f'downloading {file_hash}...')
        r = requests.get(
            url=self.url + f'/api.php?api_key={self.api_key}&action=getfile&hash={file_hash}',
            headers=self.headers,
            verify=self.verify_ssl
        )
        if r.status_code == 200:
            print(hashlib.sha256(r.content).hexdigest())
            return r.content
        return None

    def upload(self, data):
        if data is None:
            return False
        sha256 = hashlib.sha256(data).hexdigest()
        if self.mwdb.query_file(sha256, raise_not_found=False) is None:
            log.debug(f'uploading {name}...')
            result = self.mwdb.upload_file(name=sha256, content=data)
            result.add_tag(self.tag)
            return True
        return False

    def main(self):
        results = {
            'module': self.name,
            'success': True
        }
        try:
            hashes = self.get_hashes()
            for file_hash in hashes:
                data = self.download(file_hash)
                self.upload(data)
        except Exception as error:
            log.error(error)
            results['success'] = False
        return results
