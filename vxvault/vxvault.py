#!/usr/bin/env python

import re
import requests

__author__  = 'c3rb3ru5'
__version__ = '1.0.0'


class MWDBFeedsModule():

    """
    A VxVault Collector Module for mwdb-feeds
    """

    def __init__(self, config, mwdb):
        self.name    = 'vxvault'
        self.tag     = f'feed:{self.name}'
        self.url     = 'http://vxvault.net/ViriList.php'
        self.enabled = self.startup(config)
        self.mwdb    = mwdb

    def startup(self, config):
        options = ['count', 'pages']
        for option in options:
            if config.has_option(self.name, option) is False:
                log.warning(f'{self.name} section is missing the {option} option')
                return False
        self.config = config
        return True
