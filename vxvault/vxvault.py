#!/usr/bin/env python

import re
import logging
import requests

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
        self.url     = 'http://vxvault.net/ViriList.php'
        self.mwdb    = mwdb

    def startup(self, config):
        options = ['enabled', 'limit', 'pages', 'verify_ssl']
        for option in options:
            if config.has_option(self.name, option) is False:
                log.warning(f'{self.name} section is missing the {option} option')
                return False
        self.config = config
        return self.config.getboolean(self.name, 'enabled')

    def main(self) -> None:
        regFiles = re.compile(r'files\/[a-fA-F0-9]{32}.zip')
        page_limit = self.config.getint(self.name, 'limit')
        pages = self.config.getint(self.name, 'pages')
        count_limit = pages * page_limit
        for i in range(0, pages *  page_limit, page_limit):
            url = self.url + f'?s={i}&m={page_limit}'
            print(url)
            r = requests.get(url=url, verify=self.config.getboolean(self.name, 'verify_ssl'))
            matches = re.findall(regFiles, r.content.decode('utf-8'))
            print(matches)
