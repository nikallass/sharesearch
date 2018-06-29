#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser

class DefaultConfigParser(configparser.ConfigParser):
    def __init__(self):
        configparser.ConfigParser.__init__(self)


    def safe_get(self, section, option, default, allowed=None):
        try:
            result = configparser.ConfigParser.get(self, section, option)
            if allowed is not None:
                return result if result in allowed else default
            else:
                return result
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default

    def safe_getfloat(self, section, option, default, allowed=None):
        try:
            result = configparser.ConfigParser.getfloat(self, section, option)
            if allowed is not None:
                return result if result in allowed else default
            else:
                return result
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default

    def safe_getboolean(self, section, option, default, allowed=None):
        try:
            result = configparser.ConfigParser.getboolean(self, section, option)
            if allowed is not None:
                return result if result in allowed else default
            else:
                return result
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default

    def safe_getint(self, section, option, default, allowed=None):
        try:
            result = configparser.ConfigParser.getint(self, section, option)
            if allowed is not None:
                return result if result in allowed else default
            else:
                return result
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default
