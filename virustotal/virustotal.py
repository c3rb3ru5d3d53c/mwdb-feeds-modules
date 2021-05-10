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
    A VirusTotal LiveHunt Collector Module for mwdb-feeds
    """

    def __init__(self, config, mwdb):
        self.name = 'virustotal'
        self.tag = f'feed:{self.name}'
        self.url = 'https://www.virustotal.com/api/v3'
        self.enabled = self.startup(config)
        self.headers = {
            'x-apikey': self.config.get(self.name, 'api_key')
        }
        self.verify_ssl = self.config.getboolean(self.name, 'verify_ssl')
        self.limit = self.config.get(self.name, 'limit')
        self.mwdb = mwdb

    def startup(self, config):
        options = ['enabled', 'api_key', 'limit', 'verify_ssl']
        for option in options:
            if config.has_option(self.name, option) is False:
                log.warning(f'{self.name} section is missing the {option} option')
                return False
        self.config = config
        return self.config.getboolean(self.name, 'enabled')

    def vt_download(self, file_hash):
        url = self.url + f'/files/{file_hash}/download'
        r = requests.get(url=url, headers=self.headers, allow_redirects=True, verify=self.verify_ssl)
        if r.status_code == 200:
            return r.content
        return None

    def vt_delete_notification(self, notification_id):
        url = self.url + f'/intelligence/hunting_notifications/{notification_id}'
        r = requests.delete(url=url, headers=self.headers, verify=self.verify_ssl)
        if r.status_code == 200:
            log.debug(f'successfullydeleted notification_id: {notification_id}')
            return True
        log.debug(f'failed to delete notification_id: {notification_id}')
        return False

    def main(self) -> dict:
        results = {
            'module': self.name,
            'success': True
        }
        try:
            r = requests.get(url=self.url + f'/intelligence/hunting_notification_files?limit={self.limit}', headers=self.headers, verify=self.verify_ssl)
            if r.status_code == 200:
                for attribute in r.json()['data']:
                    notification_id = attribute['context_attributes']['notification_id']
                    sha256 = attribute['attributes']['sha256']
                    if self.mwdb.query_file(sha256, raise_not_found=False) is None:
                        data = self.vt_download(sha256)
                        log.debug(f'uploading {sha256}')
                        result = self.mwdb.upload_file(name=sha256, content=data)
                        result.add_tag(self.tag)
                    else:
                        log.debug(f'{sha256} already exits on the server')
                    self.vt_delete_notification(notification_id)
        except Exception as error:
            log.error(error)
            results['success'] = False
        return results
