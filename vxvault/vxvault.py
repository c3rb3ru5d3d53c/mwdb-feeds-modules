#!/usr/bin/env python

import io
import re
import magic
import hashlib
import zipfile
import logging
import requests
from requests.auth import HTTPBasicAuth

log = logging.getLogger(__name__)

__author__  = 'c3rb3ru5'
__version__ = '1.0.0'

class MWDBFeedsModule():

    """
    A VxVault Collector Module for mwdb-feeds
    """

    def __init__(self, config, mwdb):
        self.name    = 'vxvault'
        self.tag     = f'feed:{self.name}'
        self.enabled = self.startup(config)
        self.url     = 'https://vxvault.net/ViriList.php'
        self.mwdb    = mwdb
        self.headers = {'User-Agent': f'mwdb-feeds/{__version__}'}
        self.auth = HTTPBasicAuth(
            self.config.get(self.name, 'username'),
            self.config.get(self.name, 'password'))

    def startup(self, config):
        options = ['enabled', 'limit', 'pages', 'verify_ssl', 'username', 'password', 'zip_password']
        for option in options:
            if config.has_option(self.name, option) is False:
                log.warning(f'{self.name} section is missing the {option} option')
                return False
        self.config = config
        return self.config.getboolean(self.name, 'enabled')

    def send_zip_contents(self, content) -> bool:
        if magic.from_buffer(content, mime=True) != 'application/zip':
            return False
        z = zipfile.ZipFile(io.BytesIO(content))
        z.setpassword(self.config.get(self.name, 'zip_password').encode())
        for z_file in z.namelist():
            if not z_file.endswith('/'):
                data = z.read(z_file)
                name = hashlib.sha256(data).hexdigest()
                if self.mwdb.query_file(name, raise_not_found=False) is None:
                    log.debug(f'uploading {name}')
                    result = self.mwdb.upload_file(name=name, content=data)
                    result.add_tag(self.tag)
                else:
                    log.debug(f'{name} already exits on the server')
        z.close()
        return True

    def get_urls(self) -> list:
        try:
            urls = []
            regFiles = re.compile(r'files\/[a-fA-F0-9]{32}.zip')
            page_limit = self.config.getint(self.name, 'limit')
            pages = self.config.getint(self.name, 'pages')
            count_limit = pages * page_limit
            for i in range(0, pages *  page_limit, page_limit):
                url = self.url + f'?s={i}&m={page_limit}'
                print(url)
                r = requests.get(url=url, headers=self.headers, verify=self.config.getboolean(self.name, 'verify_ssl'))
                files = re.findall(regFiles, r.content.decode('utf-8'))
                for file_path in files:
                    urls.append('https://vxvault.net/' + file_path)
            return urls
        except Exception as error:
            log.error(error)
            return []

    def main(self) -> None:
        result = {
            'module': self.name,
            'success': True
        }
        try:
            urls = self.get_urls()
            for url in urls:
                r = requests.get(
                    url=url,
                    headers=self.headers,
                    auth=self.auth,
                    verify=self.config.getboolean(self.name, 'verify_ssl')
                )
                if r.status_code == 200:
                    self.send_zip_contents(r.content)
                else:
                    log.error(f'failed to access {url} with status code {r.status_code}')
        except Exception as error:
            log.error(error)
            result['success'] = False
        return result
