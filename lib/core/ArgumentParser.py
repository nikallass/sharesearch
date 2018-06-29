#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from optparse import OptionParser, OptionGroup

from lib.util.FileUtils import File
from lib.util.FileUtils import FileUtils

from lib.core.DefaultConfigParser import DefaultConfigParser

import ast

class ArgumentParser(object):
    def __init__(self, script_path):
        self.script_path = script_path
        self.parseConfig()
        self.parseArguments()

    def parseConfig(self):
        config = DefaultConfigParser()
        configPath = FileUtils.buildPath(self.script_path, "default.cfg")
        config.read(configPath)

        # General
        self.inp_encoding = config.safe_get("general", "inp_encoding", None)
        self.cmd_timeout = config.safe_get("general", "cmd_timeout_in_sec", None)
        self.tmp_filename = config.safe_get("general", "tmp_file_name_4_upload_to_write_access_check", None)
        self.cred_for_public_shares = config.safe_get("general", "cred_for_public_shares", None)

        # Spider        
        self.black_list_extensions = ast.literal_eval('["' + config.safe_get("spider", "black_list_extensions", None).strip(',').replace(',', '","') + '"]')
        self.black_list_words_in_full_path  = ast.literal_eval(config.safe_get("spider", "black_list_words_in_full_path", None))
        self.interesting_files = ast.literal_eval(config.safe_get("spider", "interesting_files", None))
        self.dirs_to_spider_in_win_folder = ast.literal_eval(config.safe_get("spider", "dirs-to-spider-in-windows-folder", None))
        self.tmp_mnt_path = config.safe_get("spider", "tmp_mnt_path", None)
        self.spider_share_timeout = config.safe_get("spider", "each_share_spider_timeout_in_min", None)

        # Grep
        self.whitelist_extensions = ast.literal_eval('["' + config.safe_get("grep", "whitelist_extensions", None).strip(',').replace(',', '","') + '"]')
        self.regular_expressions = ast.literal_eval(config.safe_get("grep", "regular_expressions", None))
        self.max_file_size_to_grep = config.safe_get("grep", "max-file-size-to-grep-kb", None)
        self.default_max_depth = config.safe_get("grep", "max_depth", None)

    def error(self, err):
        self.parser.error(err)

    def parseArguments(self):
        usage = 'Usage: \n\t%prog [options] DOMAIN/login:password HOST(s)'\
                '\n\t%prog [options] WORKGROUP/login:LM:NT HOST(s)'\
                '\n\nExamples: \n\t%prog 192.168.0.0/16'\
                '\n\t%prog "./username:PassWord" 192.168.1.0/24'\
                '\n\t%prog \'./administrator:12345\' -p all -w -v 192.168.0.0/24'\
                '\n\t%prog --spider "DOMAIN/username:PassWord" 192.168.1.0/24'\
                '\n\t%prog -s --share-num 2 --grep -i file.csv 192.168.1.62'
        self.parser = OptionParser(usage, version = '%prog 0.1_alpha', description='ShareSearch tool goes through hosts with SMB, NFS, checking credentials, looking for interesting stuff and greping sensitive data in it.')


        group_general = OptionGroup(self.parser, "General Options")
        group_general.add_option("-i", "--import", metavar="FILE", help="Import previous csv-results and print them.", dest="import_filename")
        group_general.add_option("-H", "--hosts", metavar="FILE", help="Get target hosts from input file.", dest="hosts_filename")
        group_general.add_option('-m', '--masscan', help='Use masscan instead of nmap at initial 445, 139 port scan.', action='store_true', dest='use_masscan', default=False)
        group_general.add_option('-e', '--exist', help='Declare all input (-H) hosts containing SMB shares and skip init port scan. Ranges will be removed.', action='store_true', dest='declare_exists', default=False)
        group_general.add_option("-C", "--creds", metavar="FILE", help="Get credentials from input file.", dest="creds_filename")
        group_general.add_option("-p", "--perms", metavar="[r/rw/w/no/all]", help="Shares with what permissions do we need (default r)? [r/rw/w/no/all]", dest="requested_rights", default='r')
        group_general.add_option('-w', '--check-write', help='Check write permissions trying to upload file.', action='store_true', default=False)
        group_general.add_option('-v', '--verbose', help='Be verbose. Print all findings to STDOUT.', action='store_true', dest='be_verbose', default=False)
        

        self.parser.add_option_group(group_general)

        group_spider = OptionGroup(self.parser, "Spider Options",
                    "Options for spidering files in shares. "
                    "You can manage files to spider in default.cfg")
        group_spider.add_option('-s', '--spider', help='Spider interesting files in all shares.', action='store_true', default=False)
        group_spider.add_option('-n', '--share-num', metavar='SHARE_NUM', help='Shares numbers in imported result list to spider ([,] as delimiter, [0/a/all] for "all").', dest='share_nums')
        group_spider.add_option('-d', '--depth', help='Maximum depth level of recursive spidering (default 5).', action='store', type='int', dest='max_depth', default=-1)
        group_spider.add_option('-f', '--force', help='Spider everyting in every share, even if it is already spidered. By default we also skip parsing whole "ADMIN$"" and "C$/Windows" shares to speed up (but we look for SAM, SYSTEM, hosts files.).', action='store_true', default=False)
        group_spider.add_option("-S", "--spider-print", metavar="FILE", help="Print imported Spider results with highlighting.", dest="spider_import_filename")
        group_spider.add_option('-t', '--threads', help='TODO: Number of threads while spidering (default 1).', action='store', type='int', dest='threads', default=1)
        self.parser.add_option_group(group_spider)

        group_grep = OptionGroup(self.parser, "FileGrep Options",
                    "Options for grep strings in files found by spider. "
                    "By default it doesn't grep strings in files after spidering shares. "
                    "You can manage regular expressions list in default.cfg")
        group_grep.add_option('-g', '--grep', help='Grep spidered interesting files.', action='store_true', default=False)
        group_grep.add_option('-k', '--kb-grep-size', help='Maximum filesize in KB for grep (default 200).', action='store', type='int', dest='max_file_size', default=200)
        group_grep.add_option("-G", "--grep-print", metavar="FILE", help="Print imported Grep results with highlighting.", dest="grep_import_filename")
        
        self.parser.add_option_group(group_grep)

        (self.options, self.arguments) = self.parser.parse_args()
