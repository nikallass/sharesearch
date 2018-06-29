#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: Nikita A. Medvedev <nikallass@yandex.ru>.

# Install requirements: 
# pip3 install -r requirements.txt
# sudo apt-get install cifs-utils

import os
import sys
if sys.version_info < (3, 0):
    sys.stdout.write("Sorry, sharesearch requires Python 3.x\n")
    sys.exit(1)
import datetime
import time
import re
from lib.core.ArgumentParser import ArgumentParser
from subprocess import check_output, STDOUT
#import pprint
from termcolor import colored, cprint
import csv
import ast
import traceback

class Program(object):
    print_w_share = lambda s,x: cprint(x, 'green', attrs=['bold'])
    print_r_share = lambda s,x: cprint(x, 'green')
    print_na_share = lambda s,x: cprint(x, 'blue', attrs=['dark'])
    print_finding = lambda s,x: cprint(x, 'red')
    print_debug = lambda s,x: cprint(x, 'green', attrs=['dark'])
    print_grep = lambda s,x: cprint(x, 'red', attrs=['dark'])
    print_grep_finding = lambda s,x: cprint(x, 'red', attrs=['bold'])

    right_undef = '.undef.rights.'
    right_no =    '.no....rights.'
    right_rw =    '.read.&.write.'
    right_read =  '.read.........'
    right_write = '.write........'
    right_all =   '.all..........'

    def __init__(self):
        # Init global variables
        self.scope = {} # main object to store all results
        self.scope_list = [] # object to store results as list of connection lines
        self.viewed_shares = {} # Dict to store resulting (viewed) share nums and nums in scope_list
        self.finding_results = {} # List to store spider results

        self.ips = None
        #self.pp = pprint.PrettyPrinter(indent=4)
        self.script_path = (os.path.dirname(os.path.realpath(__file__)))

        # Check if export path ./out exists
        out_dir = self.script_path + '/out'
        print(out_dir)
        if os.path.exists(out_dir):
            if not os.path.isdir(out_dir):
                os.remove(out_dir)
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        self.parser = ArgumentParser(self.script_path)
        self.export_path = ''
        self.spider_output = ''

        # Pull down options
        opts = vars(self.parser.options)
        self.share_nums = opts['share_nums']
        self.spidering = opts['spider']
        self.check_write = opts['check_write']
        self.force_spider = opts['force']
        if self.share_nums != None:
            self.spidering = True
        self.grepping = opts['grep']
        self.max_file_size = opts['max_file_size']
        self.max_depth = opts['max_depth']
        self.import_filename = opts['import_filename']
        self.grep_import_filename = opts['grep_import_filename']
        if self.grep_import_filename != None:
            self.print_imported_grep(self.grep_import_filename)
            exit()

        self.spider_import_filename = opts['spider_import_filename']
        if self.spider_import_filename != None:
            self.print_imported_spider(self.spider_import_filename)
            exit()

        self.threads = opts['threads'] # TODO: threads functionality
        self.hosts_filename = opts['hosts_filename']
        self.creds_filename = opts['creds_filename']

        self.credentials = []

        try:
            self.credentials.append(self.extract_creds(self.parser.cred_for_public_shares))
        except Exception:
            print('Error! while parsing credentials for public shares in default.cfg.')
            exit(1)

        if len(self.credentials) != 1:
            print('Error! No credentials for public shares in default.cfg, but they are required for public shares listing.')
            exit(1)
        self.local_domain = self.credentials[0][0]
        self.guest_login = self.credentials[0][1]
        self.guest_password = self.credentials[0][2]


        self.black_list_extensions = self.parser.black_list_extensions
        self.black_list_words_in_full_path = self.parser.black_list_words_in_full_path
        self.regular_expressions = self.parser.regular_expressions
        self.whitelist_extensions = self.parser.whitelist_extensions

        # Linux commands timeout
        self.cmd_timeout = str(self.parser.cmd_timeout)

        self.verbose = opts['be_verbose']

        self.use_masscan = opts['use_masscan']
        self.skip_init_scan = opts['declare_exists']

        self.dirs_to_spider_in_win_folder = self.parser.dirs_to_spider_in_win_folder
        self.default_max_depth = self.parser.default_max_depth

        if opts['requested_rights'] == 'r':
            self.requested_rights = self.right_read
        elif opts['requested_rights'] == 'rw':
            self.requested_rights = self.right_rw
        elif opts['requested_rights'] == 'w':
            self.requested_rights = self.right_write
        elif opts['requested_rights'] == 'no':
            self.requested_rights = self.right_no
        elif opts['requested_rights'] == 'all':
            self.requested_rights = self.right_all
        else:
            self.parser.error("requested wrong permissions [r/rw/w/no/all].")
            self.parser.print_help()
            exit()

        # Check if no arguments was passed
        if len(self.parser.arguments) < 1 and self.import_filename == None and self.hosts_filename == None:
            self.parser.error("incorrect number of arguments (1 at least).")
            self.parser.print_help()
            exit()

        # Load credentials from file, strip each line, and delete " quotes from beginning and at the end of line
        try:
            if self.creds_filename != None:
                creds_tmp = []
                with open(self.creds_filename, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if len(line) == 0:
                            continue
                        if line[0] == '"' and line[-1] == '"':
                            line = line[1:-1]
                        creds_tmp.append(line)
                for c in creds_tmp:
                    self.credentials.append(self.extract_creds(c))

        except Exception as e:
            traceback.print_exc()
            self.parser.error("Wrong arguments!")
            self.parser.print_help()
            traceback.print_exc()
            exit()


        ########### START WORK #############
        if len(self.parser.arguments) == 1 and self.hosts_filename == None:
            # remove CIDR ranges if --declare-exists
            if self.skip_init_scan:
                if '/' not in self.parser.arguments[0] and '\\' not in self.parser.arguments[0]:
                    self.ips = self.parser.arguments[0]
                if self.ips == None:
                    self.parser.error("Bad hostname/IP (it must not contain ranges with -e flag).")
                    exit()
            else:
                self.ips = self.parser.arguments[0]

        elif (len(self.parser.arguments) == 2) or (self.hosts_filename != None and len(self.parser.arguments) == 1):
            ##########    Write down passed arguments to vars   ##########
            try:
                self.credentials.append(self.extract_creds(self.parser.arguments[0]))
                # Hosts IPs
                if self.hosts_filename == None:
                    self.ips = self.parser.arguments[1]
            except Exception:
                self.parser.error("Wrong arguments!")
                self.parser.print_help()
                exit()

    def extract_creds(self, creds_line):
        domain = None
        login = None
        password = None
        lm_hash = None
        nt_hash = None

        m = re.search('^.*?(?=/)', creds_line)
        domain = m.group(0)

        # Grep Login
        m = re.search('(?<=/).*?(?=:)', creds_line)
        login = m.group(0)

        # Grep Password and Hashes
        # Check if user passes NTLM hashes (LM:NT)
        pass_or_hash = re.search('(?<=:).*$', creds_line).group(0)
        if len(pass_or_hash) == 65 and pass_or_hash[32] == ':': # !hashes (LM:NT)
            lm_hash = re.search('^.*(?=:)', pass_or_hash).group(0)
            nt_hash = re.search('(?<=:).*$', pass_or_hash).group(0)
        else: # No it was password
            password = pass_or_hash
        return([domain, login, password, lm_hash, nt_hash])

    def work(self):
        self.time_start_working = time.time()
        self.export_path = self.script_path + '/out/shares_' + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + '.csv'
        self.grep_path = self.export_path.replace('.csv', '_grep.txt')
        self.spider_path = self.export_path.replace('.csv', '_spider.txt')

        if self.import_filename != None:
            print('\n[============================== IMPORTING SHARES ==============================]\n')
            self.import_shares(self.import_filename)
            self.print_observe_res(self.requested_rights)
            self.time_observing_done = 0

        else:
            self.do_observe()
            print('\n[================================ SHARES FOUND ================================]\n')
            self.time_observing_done = time.time() - self.time_start_working
            #print('[.] Results:\n')
            self.print_observe_res(self.requested_rights)
            self.export_shares(self.export_path)
            print('\n[i] SMB shares scanning results are saved to: ' + self.export_path)

        # ASK for continue spidering
        if not self.spidering:
            want_to_spider = ''
            no_answer = True
            print('[i] Press Enter to proceed with defaults.')
            while no_answer:
                if no_answer:
                    want_to_spider = input("[?] Do you want to spider? [Y/n] ").lower()
                    no_answer = (want_to_spider != '' and want_to_spider != 'y' and want_to_spider != 'yes' and want_to_spider != 'no' and want_to_spider != 'n')
            if want_to_spider == 'n' or want_to_spider == 'no':
                exit()

        # Spider all shares by default
        shares_to_spider = [0]

        if self.share_nums != None:
            shares_to_spider = self.getNums(string_with_nums=self.share_nums)
        else:
            sts = self.getNums('[?] Provide share numbers from the list above (use "," or [all|a|0]) (default all): ')
            shares_to_spider = sts if sts[0] != -1 else [0]

        # Put in depth
        if self.max_depth == -1:
            md = self.getNums('[?] How much levels in depth (recursively) do you want to spider (default ' + str(self.default_max_depth) + ')? [1-100] ')[0]
            if md in range(1,100):
                self.max_depth = md
            else:
                self.max_depth = self.default_max_depth
        else:
            if self.max_depth not in range(1,100):
                self.max_depth = self.default_max_depth

        if not self.grepping:
            want_to_grep = ''
            no_answer = True
            while no_answer:
                if no_answer:
                    want_to_grep = input("[?] Do you want to grep? [Y/n] ").lower()
                    no_answer = (want_to_grep != '' and want_to_grep != 'y' and want_to_grep != 'yes' and want_to_grep != 'no' and want_to_grep != 'n')
            if want_to_grep == 'n' or want_to_grep == 'no':
                self.grepping = False
            else:
                self.grepping = True

        try:
            self.time_start_spidering = time.time()

            self.do_spider(shares_to_spider)

            self.print_debug('\nObserving done in ' + str(self.time_observing_done)[:10] + ' seconds.')
            self.print_debug('Spidering ' + ('and grepping ' if self.grepping else '') + 'done in ' + str(time.time() - self.time_start_spidering)[:10] + ' seconds.')
        except KeyError as e:
            print('[' + str(e.args[0]) + '] Requested share index ' + str(e.args[0]) + ' not listed.')
        finally:
            self.unmout_share()



    def do_observe(self):
        # Scan all ip-s for hosts with 445 and 139 ports open
        #ips_with_smb = self.masscan_scan_smb_hosts(self.ips, inp_file=self.hosts_filename)
        ips_with_smb = []
        if self.skip_init_scan:
            if self.hosts_filename == None:
                ips_with_smb = self.ips.split(' ')
            else:
                with open(self.hosts_filename, newline='') as hosts_file:
                    for row in hosts_file:
                        r = row.strip()
                        if '/' not in r and '\\' not in r and r != '':
                            ips_with_smb.append(r)
                            #check_this 'if-else' block
                print('[i] Got ' + str(len(ips_with_smb)) + ' host targets from file: ' + self.hosts_filename)
        elif self.use_masscan:
            print('\n[============================== COLLECTING HOSTS ==============================]\n')
            #SMB
            print('[.] SMB: Collecting hosts with 445 and 139 ports opened via "masscan".')
            ips_with_smb = self.masscan_scan_smb_hosts(self.ips, inp_file=self.hosts_filename)
            print('    [i] SMB: Found ' + str(len(ips_with_smb)) + ' host' + ('s' if len(ips_with_smb) != 1 else '') + '.')
            #NFS
            print('[.] NFS: Collecting hosts with 111 port opened via "masscan".')
            ips_with_nfs = self.masscan_scan_nfs_hosts(self.ips, inp_file=self.hosts_filename)
            print('    [i] NFS: Found ' + str(len(ips_with_nfs)) + ' host' + ('s' if len(ips_with_nfs) != 1 else '') + '.')
        else:
            print('\n[============================== COLLECTING HOSTS ==============================]\n')
            #SMB
            print('[.] SMB: Collecting hosts with 445 and 139 ports opened via "nmap -sT".')
            ips_with_smb = self.nmap_scan_smb_hosts(self.ips, inp_file=self.hosts_filename)
            print('    [i] SMB: Found ' + str(len(ips_with_smb)) + ' host' + ('s' if len(ips_with_smb) != 1 else '') + '.')
            #NFS
            print('[.] NFS: Collecting hosts with 111 and 2049 ports opened via "nmap -sT".')
            ips_with_nfs = self.nmap_scan_nfs_hosts(self.ips, inp_file=self.hosts_filename)
            print('    [i] NFS: Found ' + str(len(ips_with_nfs)) + ' host' + ('s' if len(ips_with_nfs) != 1 else '') + '.')

        print('\n[============================== OBSERVING SHARES ==============================]\n')        # print('[.] Collecting Public shares on each host via "smbclient -L".')
        if len(ips_with_smb) == 0 and len(ips_with_nfs) == 0:
            print('[!] No hosts with available shares found! Quitting.')
            exit()
        # ##############   COLLECT IP LISTINGS   ####################
        # # 1) Collect via smbclient. Connect to each previously nmapped host
        # # For every ip, check shares listing with Guest creds (public)
        # for ip in ips_with_smb:
        #     shares = self.smbclient_list_shares(ip, nt_hash=None, domain=self.local_domain, login=self.guest_login)
        #     if len(shares) > 0:
        #         print('    [i] Found ' + str(len(shares)) + ' possible share(s) on host ' + ip)
        #         self.add_ip_to_scope(ip, self.request_nbt_name(ip))
        #     for s in shares:
        #         if s not in self.scope[ip][1]:
        #             self.scope[ip][1][s] = {}
        #         self.scope[ip][1][s][(self.local_domain, self.guest_login)] = [self.guest_password, None, None, self.right_undef, []]
        #if False:
        print('[.] SMB: Collecting Public shares and privs on each host via "nmap smb-enum-shares.nse".')
        # 2) nmap script can enumerate unavailable shares - more (useless) results
        # NMAP often results READ access - but it is mistake,
        # it interpres listing of shares as READ access, but it is false positive
        # so we will recheck rigts below with smbclient.py
        # Fill in guest access rights with nmap:
        i_list = ''
        for i in ips_with_smb:
            i_list += i + ' '
        rights_nmap = self.nmap_enum_smb_shares(i_list)
        for n_ip in rights_nmap:
            self.add_ip_to_scope(n_ip, self.request_nbt_name(n_ip))
            if len(rights_nmap[n_ip]) > 0:
               print('    [i] SMB: Found ' + str(len(rights_nmap[n_ip])) + ' possible share' + ('s' if len(rights_nmap[n_ip]) != 1 else '') + ' on host ' + n_ip )
            for s in rights_nmap[n_ip]:
                if s not in self.scope[n_ip][1]:
                    self.scope[n_ip][1][s] = {}
                if (self.local_domain, self.guest_login) not in self.scope[n_ip][1][s]:
                    self.scope[n_ip][1][s][(self.local_domain, self.guest_login)] = [self.guest_password, None, None, '', []]
                self.scope[n_ip][1][s][(self.local_domain, self.guest_login)][3] = rights_nmap[n_ip][s]


        print('[.] SMB: Collecting shares via "smbclient -L".')
        # Get shares with authorized access
        for c in self.credentials:
            for ip in ips_with_smb:
                #print(ips_with_smb)
                #exit()
                shares = self.smbclient_list_shares(ip, nt_hash=c[4], password=c[2], domain=c[0], login=c[1])
                if len(shares) > 0:
                    print('    [i] SMB: Found ' + str(len(shares)) + ' possible share' + ('s' if len(shares) != 1 else '') + ' on host ' + ip + ' with creds: "' + c[0] + '/' + c[1] + ':' + (c[2] if c[2] != None else "00000000000000000000000000000000:" + c[4] ) + '"')
                    self.add_ip_to_scope(ip, self.request_nbt_name(ip))
                for s in shares:
                    if s not in self.scope[ip][1]:
                        self.scope[ip][1][s] = {}
                    self.scope[ip][1][s][(c[0], c[1])] = [c[2], c[3], c[4], self.right_undef, []]


        print('[.] SMB: Collecting rights connecting to hosts via "smbclient".')
        ##############  recheck & COLLECT R\W RIGHTS with authorized access  ####################
        ## smbcacls CANT use pw-hash - BUG
        #  so we will go bad way - smbclient
        #  Fill down privs with authorized access
        for ip in self.scope:
            host = self.scope[ip][1]
            for share in host:
                for domain_login in host[share]:
                    nthash = None if host[share][domain_login][2] == 'None' else host[share][domain_login][2]
                    passwd = None if host[share][domain_login][0] == 'None' else host[share][domain_login][0]
                    tmp_right = self.smbclient_get_privs(ip, share, test_write_access=self.check_write, domain=domain_login[0], login=domain_login[1], nt_hash=nthash, password=passwd)
                    host[share][domain_login][3] = tmp_right

        print('[.] NFS: Collecting shares via "nmap nfs-showmount.nse".')
        # 2) nmap script can enumerate unavailable shares - more (useless) results
        # Fill in access rights with nmap:

        rights_nmap = {}
        for i in ips_with_nfs:
            i_r = None
            i_r = self.nmap_enum_nfs_shares(i) # returns { 'share' : ['CIDR', right-undef] }
            if i_r != None and len(i_r) > 0:
                rights_nmap[i] = i_r # {ip : {'share': ['cidr, 'right-undef']}}
                if len(rights_nmap[i]) > 0:
                    print('    [i] NFS: Found ' + str(len(rights_nmap[i])) + ' possible share' + ('s' if len(rights_nmap[i]) > 1 else '') + ' on host ' + i )

        print('[.] NFS: Collecting rights via "nmap nfs-ls.nse".')

        # rights_nmap = {'IP': {sharename: ['allow_ip', 'right']}}
        rights_nmap = self.nmap_get_nfs_shares_rights(rights_nmap)


        for n_ip in rights_nmap:
            self.add_ip_to_scope(n_ip, self.request_nbt_name(n_ip))

            for s in rights_nmap[n_ip]:
                allowed_ips = rights_nmap[n_ip][s][0]
                if s not in self.scope[n_ip][1]:
                    self.scope[n_ip][1][s] = {}
                if ('', allowed_ips) not in self.scope[n_ip][1][s]:
                    self.scope[n_ip][1][s][('', allowed_ips)] = ['', None, None, '', []]
                self.scope[n_ip][1][s][('', allowed_ips)][3] = rights_nmap[n_ip][s][1]


    def do_spider(self, share_list=[0]):
        self.scope_to_list()
        print('\n[============================== SPIDERING SHARES ==============================]\n')
        already_spidered = []
        count_finding_in_all_shares = 0
        spider_list_with_pth = []
        if len(share_list) == 0:
            print('No shares to spider')
            return()
        elif share_list[0] == 0:
            spider_list_with_pth = self.viewed_shares.keys()
        else:
            spider_list_with_pth = share_list


        # Remove all pth shares
        spider_list = []
        for sl in spider_list_with_pth:
            nt_hash = self.scope_list[self.viewed_shares[sl]][7]
            lm_hash = self.scope_list[self.viewed_shares[sl]][6]
            if lm_hash == None and nt_hash == None:
                spider_list.append(sl)
        if len(spider_list) != len(spider_list_with_pth) and self.verbose:
            self.print_debug('[x] TODO: mount shares with pass-the-hash (now skipping them).')

        for sl in spider_list:
            #["IP","NBTNAME","SHARENAME","WORKGROUP_DOMAIN","LOGIN","PASSWORD","LM_HASH","NT_HASH","PRIV"]
            share_num = self.viewed_shares[sl]
            share_line = self.scope_list[share_num]
            share = self.scope_list[share_num][2]
            ip = self.scope_list[share_num][0]
            login = self.scope_list[share_num][4]
            domain = self.scope_list[share_num][3]
            nt_hash = self.none_to_empty(self.scope_list[share_num][7])
            pwd = self.scope_list[share_num][5]
            password = self.none_to_empty(pwd)
            pass_or_hash = password if pwd != None else nt_hash

            is_smb_share = True if share[0] != '/' else False

            #---If creds = Guest, check if we have other creds to spider
            we_have_auth_for_share = False
            if not self.force_spider and is_smb_share:
                for tmp_sl in spider_list:
                    tmp_share_num = self.viewed_shares[tmp_sl]
                    tmp_share = self.scope_list[tmp_share_num][2]
                    tmp_ip = self.scope_list[tmp_share_num][0]
                    tmp_login = self.scope_list[tmp_share_num][4]
                    if ip == tmp_ip and tmp_share.lower() == share.lower() and tmp_login.lower() != 'guest' and login.lower() == 'guest':
                        we_have_auth_for_share = True
            if we_have_auth_for_share and is_smb_share:
                if self.verbose:
                    self.print_debug('[' + str(sl) + '] "smb://' + ip + '/' + share + '" - scipping "Guest" anonymous auth as we have other more precise credentials.')
                continue

            #---Check if we have C$ share in scope, lets do not spider admin$------
            we_have_c_share = False
            if not self.force_spider and share.lower() == 'admin$' and is_smb_share:
                for tmp_sl in spider_list:
                    tmp_share_num = self.viewed_shares[tmp_sl]
                    tmp_share = self.scope_list[tmp_share_num][2]
                    tmp_ip = self.scope_list[tmp_share_num][0]
                    if ip == tmp_ip and tmp_share.lower() == 'c$':
                        we_have_c_share = True
            if we_have_c_share and is_smb_share:
                if self.verbose:
                    self.print_debug('[' + str(sl) + '] "smb://' + ip + '/' + share + '" - scipping ADMIN$ share as we have C$ on this host (check --force option).')
                continue
            #----------------------------------------------------------------------


            #----Don't spider previously parced share with another creds-----------
            if not self.force_spider and is_smb_share and (ip + '/' + share) in already_spidered:
                if self.verbose:
                    self.print_debug('[' + str(sl) + '] "smb://' + ip + '/' + share + '" - scipping previously parced share (check --force option)')
                continue
            #----------------------------------------------------------------------

            mount_msg = self.mount_share(share=share,
                                ip=ip,
                                nt_hash=nt_hash,
                                login=login,
                                password=password,
                                domain=domain,
                                is_smb=is_smb_share)
            if mount_msg == 'success':
                spidering_out_str = ''
                if is_smb_share: # SMB
                    spidering_out_str = '[' + str(sl) + '] "smb://' + ip + '/' + share + '" - spidering '
                    if self.grepping:
                        spidering_out_str += 'and grepping '
                    spidering_out_str += 'share with: "' + domain + '/' + login + ':' + pass_or_hash + '"'
                    print(spidering_out_str)
                else: # NFS
                    spidering_out_str = '[' + str(sl) + '] "nfs://' + ip + ':' + share + '" - spidering '
                    if self.grepping:
                        spidering_out_str += 'and grepping '
                    spidering_out_str += 'share.'
                    print(spidering_out_str)
                self.spider_output += spidering_out_str + '\n'
                mnt_path = self.parser.tmp_mnt_path
                # Crafting find command

                #---------------exclude C:\Windows if C$, ADMIN$------------------
                # TODO: Smart Windows folder recognition
                exclude_path = ''
                find_cmd_exclude = ''
                if not self.force_spider and share.lower() == "c$":
                    exclude_path = mnt_path + '/Windows'
                    find_cmd_exclude = '-path ' + exclude_path + ' -prune -o'
                elif not self.force_spider and share.lower() == 'admin$':
                    exclude_path = mnt_path
                    find_cmd_exclude = '-path ' + exclude_path + ' -prune -o'
                #------------------------------------------------------------------

                find_cmd_start = 'find ' + mnt_path + ' -maxdepth ' + str(self.max_depth) + ' ' + find_cmd_exclude + ' -type f \( '
                find_cmd_middle = ''
                interesting_files = self.parser.interesting_files
                first_word = True
                for word in interesting_files:
                    if first_word:
                        find_cmd_middle += '-iname "' + word + '" '
                        first_word = False
                    else:
                        find_cmd_middle += '-o -iname "' + word + '" '
                find_cmd_end = '\) || true'

                find_cmd = find_cmd_start + find_cmd_middle + find_cmd_end

                output = check_output(find_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)
                found_paths = output.strip().split('\n')

                # Finding special paths in C:\Windows if we excluded it.
                if not self.force_spider:
                    if share.lower() == "c$" or share.lower() == 'admin$':
                        if self.verbose:
                            self.print_debug('[i] In "Windows" directory only several paths are checked (look at --force option).')

                        find_cmd_start = 'find '

                        win_in_share_path = '/'
                        if share.lower() == 'c$':
                            win_in_share_path += 'Windows/'
                        for path in self.dirs_to_spider_in_win_folder:
                            find_cmd_start += mnt_path + win_in_share_path + path.replace('\\','/').strip('/') + ' '
                        find_cmd_start += '-maxdepth 1 -type f \( '

                        find_cmd = find_cmd_start + find_cmd_middle + find_cmd_end
                        output = check_output(find_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)
                        for o in output.strip().split('\n'):
                            found_paths.append(o)
                for p in found_paths:
                    path_contains_black_list_word = False
                    # Filter blacklist words from config file
                    for blw in self.black_list_words_in_full_path:
                        if blw in p:
                            path_contains_black_list_word = True
                    # Filter find command errors
                    if (not path_contains_black_list_word) and p != '' and ('Permission denied' not in p) and ('Resource temporarily unavailable' not in p) and ('No such file or directory' not in p) and (p.strip() != exclude_path):
                        finding_extension = p.strip().strip('"').split('.')[-1]
                        if finding_extension in self.black_list_extensions:
                            continue
                        path_in_share = p.replace(mnt_path, '')
                        finding_path_str = p.replace(mnt_path, 'smb://' + ip + '/' + share)
                        fining_out = ' - "' + finding_path_str + '"'
                        if self.verbose:
                            self.print_finding(fining_out)
                        self.spider_output += fining_out + '\n'
                        #["IP","NBTNAME","SHARENAME","WORKGROUP_DOMAIN","LOGIN","PASSWORD","LM_HASH","NT_HASH","PRIV"]
                        if str(share_line) not in self.finding_results:
                            self.finding_results[str(share_line)] = {}
                        self.finding_results[str(share_line)][path_in_share] = ('',0)

                        count_finding_in_all_shares += 1

                        if self.grepping:
                            #__________________________ DO_GREP__________________________
                            try:
                                share_file_size = "%.0f" % (os.path.getsize(p) / 1024)
                                if int(share_file_size) <= int(self.parser.max_file_size_to_grep) and finding_extension in self.whitelist_extensions:

                                    grep_cmd = 'grep "' + p + '" -r -A 3 -B 3 -aniPe "'
                                    for r in self.regular_expressions[:-1]:
                                        grep_cmd += r + '|'
                                    grep_cmd += self.regular_expressions[-1] + '" || true'
                                    output = check_output(grep_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)

                                    # There were problems in grepping windows cp1251 cyrillic chars, so I add one more grep to find out cyrillic words
                                    grep_cmd_cp1251 = 'cat "' + p + '" | iconv -f cp1251 |' + 'grep - -r -A 3 -B 3 -aniPe "'
                                    for r in self.regular_expressions[:-1]:
                                        if self.has_cyrillic(r):
                                            grep_cmd_cp1251 += r + '|'
                                    grep_cmd_cp1251 += self.regular_expressions[-1] + '" || true'

                                    output_cp1251 = check_output(grep_cmd_cp1251, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)

                                    if output_cp1251.strip() != '':
                                        output += output_cp1251

                                    self.finding_results[str(share_line)][path_in_share] = (output, sl)


                            except OSError as e:
                                if self.verbose:
                                    self.print_finding('[x] ' + finding_path_str + ' - error occurs while trying to grep: ' + e.strerror)

                already_spidered.append(ip + '/' + share)
                self.unmout_share()
            elif mount_msg == 'pth':
                self.print_debug('[' + str(sl) + '] Can\'t mount share with pass-the-hash (TODO): ' + domain + '/' + login + ':' + nt_hash)
            else:
                self.print_debug('[' + str(sl) + '] Can\'t mount share: ' + mount_msg)

        self.write_spider_finging()

        grep_findings = 0
        if self.grepping:
            grep_findings = self.write_out_grep_fingings()


        print('\n[=================================== RESULTS ==================================]\n')
        print('[i] SMB shares scanning results are saved to: ' + self.export_path)

        if count_finding_in_all_shares == 0:
            print('[-] No spider results.')
            os.remove(self.spider_path)
        else:
            print('[i] Spidered ' + str(count_finding_in_all_shares) + ' interesting files. Paths saved to: ' + self.spider_path )

        if grep_findings == 0 and self.grepping:
            print('[-] No grep results.')
            os.remove(self.grep_path)
        else:
            print('[i] Grepped ' + str(grep_findings) + ' results. Findings saved to: ' + self.grep_path)

    def has_cyrillic(self, text):
        return bool(re.search('[\u0400-\u04FF]', text))

    def write_spider_finging(self):
        with open(self.spider_path, 'w') as f:
            f.write('')
        with open(self.spider_path, 'a') as f:
            f.write(self.spider_output + '\n')

    def write_out_grep_fingings(self):
        exts = ''
        for ext in self.whitelist_extensions[:-1]:
            exts += ext + ', '
        exts += self.whitelist_extensions[-1]

        grep_findings = 0

        with open(self.grep_path, 'w') as f:
            f.write('')
        for conn_str in self.finding_results:
            for share_line in self.finding_results[conn_str]:
                if self.finding_results[conn_str][share_line] == None:
                    continue

                grep_output = self.finding_results[conn_str][share_line][0]
                viewnum = self.finding_results[conn_str][share_line][1]

                if viewnum != 0 and grep_output != '':

                    conn_list = ast.literal_eval(conn_str)
                    nt_h = conn_list[7]
                    lm_h = conn_list[6]

                    if lm_h == '':
                        lm_h = '00000000000000000000000000000000'

                    if nt_h == None or lm_h == None:
                        ntlm_h = ''
                    else:
                        ntlm_h = lm_h + ':' + nt_h

                    passwd = conn_list[5]
                    pass_or_hash = conn_list[5] if passwd != None else ntlm_h
                    domain = conn_list[3]
                    login = conn_list[4]
                    nbt = conn_list[1]
                    share = conn_list[2]
                    is_smb = True if share[0] != '/' else False
                    ip = conn_list[0]

                    if grep_findings == 0 and self.verbose:
                        print('\n[========================== GREP FINDINGS IN SHARES ===========================]\n')

                    finding_title = ''
                    if is_smb:
                        finding_title = '[' + str(viewnum) + '] "smb://' + ip + '/' + share + '" (' + nbt + ') with creds "' + domain + '/' + login + ':' + pass_or_hash + '"\t[' + share_line + ']'
                    else:
                        finding_title = '[' + str(viewnum) + '] "nfs://' + ip + ':' + share + '"[' + share_line + ']'

                    if self.verbose:
                        print(finding_title + '\n')

                    with open(self.grep_path, 'a') as f:
                        f.write(finding_title + '\n\n')
                        f.write(grep_output + '\n')
                    if self.verbose:
                        for line in grep_output.split('\n'):
                            if re.search(r'^\d+:', line) != None:
                                self.print_grep_finding(line)
                            else:
                                self.print_grep(line)
                    grep_findings += 1
        return(grep_findings)

    def print_imported_grep(self, grep_file_path):
        with open(grep_file_path, 'r') as f:
            for line in f:
                if re.search(r'^\d+:', line) != None:
                    self.print_grep_finding(line.strip())
                elif re.search(r'^\[\d+\] ', line) != None:
                    print(line.strip())
                else:
                    self.print_grep(line.strip())

    def print_imported_spider(self, spider_file_path):
        with open(spider_file_path, 'r') as f:
            for line in f:
                if re.search(r' \- "', line) != None:
                    self.print_finding(line.strip())
                else:
                    print(line.strip())

    # Unfortunately mount -f cifs doesn't work with pass the hash. Only password mount
    # TODO: Mounting with Pass The Hash
    def mount_share(self, share, ip, nt_hash=None, login=None, password=None, domain='.', is_smb=True):
        tmp_mnt_path = self.parser.tmp_mnt_path

        # Check if mnt dir exists. If not, create it, if it is not dir, but file, delete it first. 
        if os.path.exists(tmp_mnt_path):
            if not os.path.isdir(tmp_mnt_path):
                os.remove(tmp_mnt_path)
            else:
                self.unmout_share()

        os.makedirs(tmp_mnt_path)
            
        if is_smb: #SMB share
            mnt_cmd_tmpl = 'mount -t cifs -o "user={0},pass={1}" "//{2}/{3}" ' + tmp_mnt_path + ' 2>&1 || true'
            if nt_hash == '': # Do mount with password auth
                mnt_cmd = mnt_cmd_tmpl.format(login, password, ip, share)
                #print(mnt_cmd)
                output = check_output(mnt_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)
                if output != '':
                    return(output.split('\n')[0])
                return('success')
            else: # Do mount with hash auth
                return('pth')
        else: # NFS share
            mnt_cmd_tmpl = 'mount -t nfs "{0}:{1}" "' + tmp_mnt_path + '" 2>&1 || true'
            mnt_cmd = mnt_cmd_tmpl.format(ip, share)
            output = check_output(mnt_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)
            if output != '':
                return(output.split('\n')[0])
            return('success')

    def unmout_share(self):
        check_mount_cmd = 'mount'
        mnt_path = self.parser.tmp_mnt_path
        output = check_output(check_mount_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)
        if mnt_path in output:
            umount_cmd = 'umount -l ' + mnt_path + ' 2>&1'
            output = check_output(umount_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)

        # Delete tmp mount dir. 
        if os.path.exists(mnt_path):
            if not os.path.isdir(mnt_path):
                os.remove(mnt_path)
            else:
                os.rmdir(mnt_path)

        #TODO: umount -f /PATH/OF/BUSY-NFS(NETWORK-FILE-SYSTEM)


    def getNums(self, prompt='№-s devided by ",": ', string_with_nums=None):

        res = []
        if string_with_nums != None:
            for i in string_with_nums.strip(',').split(','):
                if i.lower() == 'all' or i.lower() == 'a':
                    return([0])
                elif i == '':
                    return([-1])
                else:
                    res.append(int(i.strip()))
            return(res)

        while True:
            try:
                for i in input(prompt).strip(',').split(','):
                    if i.lower() == 'all' or i.lower() == 'a':
                        return([0])
                    elif i == '':
                        return([-1])
                    else:
                        res.append(int(i.strip()))
                break
            except (ValueError, NameError):
                print('Numbers only, please.')
        return(res)

    def import_shares(self, filename):
        self.export_path = filename
        self.grep_path = filename.replace('.csv', '_grep.txt')
        self.spider_path = filename.replace('.csv', '_spider.txt')
        with open(filename, newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter=',', quotechar='"')
            next(reader)  # skip the headers
            for row in reader:
                if row[0] not in self.scope:
                    self.scope[row[0]] = [self.str_to_none(row[1]), {}]
                if row[2] not in self.scope[row[0]][1]:
                    self.scope[row[0]][1][row[2]] = {}
                password = self.str_to_none(row[5])

                lm_hash = self.str_to_none(row[6])
                nt_hash = self.str_to_none(row[7])
                rights = self.str_to_none(row[8])
                self.scope[row[0]][1][row[2]][(row[3], row[4])] = [password, lm_hash, nt_hash, rights, []]
        self.scope_to_list()
        return(self.scope)

    def export_shares(self, filename):
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

            writer.writerow(['IP', 'NBTNAME', 'SHARENAME', 'WORKGROUP_DOMAIN', 'LOGIN', 'PASSWORD', 'LM_HASH', 'NT_HASH', 'PRIV'])
            for ip in self.scope:
                if ip.strip() == '':
                    continue
                host = self.scope[ip][1]
                for share in host:
                    for domain_login in host[share]:
                        creds = host[share][domain_login]
                        row = [ip, self.none_to_str(self.scope[ip][0]), share, domain_login[0], domain_login[1], self.none_to_str(creds[0]), self.none_to_str(creds[1]), self.none_to_str(creds[2]), self.none_to_str(creds[3])]
                        writer.writerow(row)


    def smbclient_list_share_dir(self, share, ip, nt_hash=None, login=None, password=None, domain='.', directory=''):
        list_share_cmd_tmpl = 'timeout --preserve-status {5} smbclient -U {0}%{1} --command="dir {2}" --pw-nt-hash //{3}/{4}  || true'
        list_share_cmd = list_share_cmd_tmpl.format(domain, login, directory, ip, share, self.cmd_timeout)
        output = check_output(list_share_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)
        print(output)


    # Get privilege for share via smbclient
    def smbclient_get_privs(self, ip, share, test_write_access=False, nt_hash=None, password=None, domain='.', login=None):
        # echo 'dir' | smbclient -U Guest -N //192.168.0.69/5
        # If responce contains 'blocks available' word, then we got read access
        # We also can write small file (self.parser.tmp_mnt_path).
        # So we can check write access but it is VERY intrusive!!

        res = self.right_undef
        check_read_cmd = ''
        check_write_cmd = ''
        curr_task = 'guest'

        if nt_hash == None and password == None and (login == None or login.lower() == 'guest'):
            curr_task = 'guest'
        elif nt_hash == None and password == None and login != None:
            curr_task = 'user-no-pass'
        elif nt_hash == None and password != None and login != None:
            curr_task = 'login-pass'
        elif nt_hash != None and password == None and login != None:
            curr_task = 'nt-hash'
        else:
            return(res)

        if curr_task == 'guest':
            check_read_cmd = 'echo "dir" | timeout --preserve-status {2} smbclient -U Guest -N "//{0}/{1}" || true'.format(ip, share, self.cmd_timeout)
            check_write_cmd = 'cd ' + self.script_path + '; echo "put {0}\\nrm {1}" | timeout --preserve-status {4} smbclient -U Guest -N "//{2}/{3}" || true'.format(self.parser.tmp_filename, self.parser.tmp_filename, ip, share, self.cmd_timeout)
        elif curr_task == 'user-no-pass':
            check_read_cmd = 'echo "dir" | timeout --preserve-status {4} smbclient -W "{0}" -U "{1}" -N "//{2}/{3}" || true'.format(domain, login, ip, share, self.cmd_timeout)
            check_write_cmd = 'cd ' + self.script_path + '; echo "put {0}\\nrm {1}" | timeout --preserve-status {6} smbclient -W "{2}" -U "{3}" -N "//{4}/{5}" || true'.format(self.parser.tmp_filename, self.parser.tmp_filename, domain, login, ip, share, self.cmd_timeout)
        elif curr_task == 'login-pass':
            check_read_cmd = 'echo "dir" | timeout --preserve-status {5} smbclient -W "{0}" -U "{1}%{2}" "//{3}/{4}" || true'.format(domain, login, password, ip, share, self.cmd_timeout)
            check_write_cmd = 'cd ' + self.script_path + '; echo "put {0}\\nrm {1}" | timeout --preserve-status {7} smbclient -W "{2}" -U "{3}%{4}" "//{5}/{6}" || true'.format(self.parser.tmp_filename, self.parser.tmp_filename, domain, login, password, ip, share,self.cmd_timeout)
        elif curr_task == 'nt-hash':
            check_read_cmd = 'echo "dir" | timeout --preserve-status {5} smbclient -W "{0}" -U "{1}%{2}" --pw-nt-hash "//{3}/{4}" || true'.format(domain, login, nt_hash, ip, share, self.cmd_timeout)
            check_write_cmd = 'cd ' + self.script_path + '; echo "put {0}\\nrm {1}" | timeout --preserve-status {7} smbclient -W "{2}" -U "{3}%{4}" --pw-nt-hash "//{5}/{6}" || true'.format(self.parser.tmp_filename, self.parser.tmp_filename, domain, login, nt_hash, ip, share, self.cmd_timeout)
        output = check_output(check_read_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)

        if 'blocks available' in output:
            res = self.right_read
        else:
            res = self.right_no
        if test_write_access:
            output = check_output(check_write_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)
            if 'putting file' in output and 'average' in output:
                res = self.right_rw
        return(res)

    def scope_to_list(self):
        # self.scope_list
        for ip in self.scope:
            if ip.strip() == '':
                continue
            shares = self.scope[ip][1]
            for share in shares:
                for domain_login in shares[share]:
                    password = shares[share][domain_login][0]
                    lm_hash = shares[share][domain_login][1]
                    nt_hash = shares[share][domain_login][2]
                    priv = shares[share][domain_login][3]
                    nbtname = self.scope[ip][0]
                    domain = domain_login[0]
                    login = domain_login[1]
                    # "IP","NBTNAME","SHARENAME","WORKGROUP_DOMAIN","LOGIN","PASSWORD","LM_HASH","NT_HASH","PRIV"
                    self.scope_list.append([ip, nbtname, share, domain, login, password, lm_hash, nt_hash, priv])
        return(self.scope_list)

    def print_observe_res(self, access, login=None):
        #print()
        found = 0
        current_id_in_scope = 0
        for ip in self.scope:
            if ip.strip() == '':
                continue
            is_smb_share = True
            shares = self.scope[ip][1]
            for share in shares:
                if share[0] == '/':
                    is_smb_share = False
                for domain_login in shares[share]:
                    password = shares[share][domain_login][0]
                    nt_hash = shares[share][domain_login][2]
                    priv = shares[share][domain_login][3]
                    pass_or_hash = ''
                    if password != None:
                        pass_or_hash = password
                    elif nt_hash != None:
                        pass_or_hash = nt_hash
                    # requested R
                    # res - will be started with finding number "[1] "
                    res_str = ''
                    nbt_nm = self.scope[ip][0]
                    if is_smb_share:
                        res_str = priv + ' "smb://' + ip + '/' + share + '" ' + (('\t(' + nbt_nm + ')') if nbt_nm != '' else '')  + ' with creds: "' + domain_login[0] + '/' + domain_login[1] + ':' + pass_or_hash + '"'
                    else: # is NFS share
                        res_str = priv + ' "nfs://' + ip + ':' + share + '" ' + (('\t(' + nbt_nm + ')') if nbt_nm != '' else '')  + ' for hosts in: "' + domain_login[1] + '"'
                    if access == self.right_read and (priv == self.right_read or priv == self.right_rw):
                        found += 1
                        if priv == self.right_read:
                            self.print_r_share('[' + str(found) + '] ' + res_str)
                            self.viewed_shares[found] = current_id_in_scope
                        else:
                            self.print_w_share('[' + str(found) + '] ' + res_str)
                            self.viewed_shares[found] = current_id_in_scope
                    # requested RW
                    elif access == self.right_rw and priv == self.right_rw:
                        found += 1
                        self.print_w_share('[' + str(found) + '] ' + res_str)
                        self.viewed_shares[found] = current_id_in_scope
                    # requested W
                    elif access == self.right_write and (priv == self.right_write or priv == self.right_rw):
                        found += 1
                        if priv == self.right_write:
                            self.print_r_share('[' + str(found) + '] ' + res_str)
                            self.viewed_shares[found] = current_id_in_scope
                        else:
                            self.print_w_share('[' + str(found) + '] ' + res_str)
                            self.viewed_shares[found] = current_id_in_scope
                    # requested undefined
                    elif access == self.right_undef:
                        found += 1
                        if priv == self.right_read or priv == self.right_write:
                            self.print_r_share('[' + str(found) + '] ' + res_str)
                            self.viewed_shares[found] = current_id_in_scope
                        elif priv == self.right_rw:
                            self.print_w_share('[' + str(found) + '] ' + res_str)
                            self.viewed_shares[found] = current_id_in_scope
                        else:
                            self.print_na_share('[' + str(found) + '] ' + res_str)
                            self.viewed_shares[found] = current_id_in_scope
                    # requested all rights
                    elif access == self.right_all:
                        found += 1
                        if priv == self.right_read or priv == self.right_write:
                            self.print_r_share('[' + str(found) + '] ' + res_str)
                            self.viewed_shares[found] = current_id_in_scope
                        elif priv == self.right_rw:
                            self.print_w_share('[' + str(found) + '] ' + res_str)
                            self.viewed_shares[found] = current_id_in_scope
                        else:
                            self.print_na_share('[' + str(found) + '] ' + res_str)
                            self.viewed_shares[found] = current_id_in_scope
                    elif access == self.right_no and priv == self.right_no:
                            found += 1
                            self.print_na_share('[' + str(found) + '] ' + res_str)
                            self.viewed_shares[found] = current_id_in_scope

                    current_id_in_scope += 1

        if found == 0:
            print('[!] Shares with requested pemissions NOT FOUND.')
            exit()

    def add_ip_to_scope(self, ip, nbtname=''):
        if ip not in self.scope:
            self.scope[ip] = ['', {}]
        self.set_nbt_name(ip, nbtname)

    def set_nbt_name(self, ip, nbtname):
        if ip not in self.scope:
            return(False)
        if self.scope[ip][0] == '':
            self.scope[ip][0] = nbtname
        return(True)

    def get_nbt_name(self, ip):
        res = None
        if ip in self.scope:
            res = scope[ip][0]
        return(res)

    def none_to_empty(self, st):
        if st == None:
            return('')
        return(st)

    def empty_to_none(self, ob):
        if ob == '':
            return(None)
        return(ob)

    def none_to_str(self, st):
        if st == None:
            return('None')
        return(st)

    def str_to_none(self, ob):
        if ob == 'None':
            return(None)
        return(ob)

    # Linux binary smbclient list shares
    def smbclient_list_shares(self, ip, nt_hash=None, password=None, domain='.', login='Guest'):
        timeout_str = ' timeout --preserve-status {0} '.format(self.cmd_timeout)
        get_shares_str = ''
        if password != None:
            shares_str = '{0} smbclient -U "{1}%{2}" -g -W {3} -I {4} -L {5} 2>&1 | sed -e "/Reconnecting/ {{ N; d; }}" | grep -P "\|" | cut -d "|" -f 2'
            get_shares_str = shares_str.format(timeout_str, login, password, domain, ip, ip)
        elif nt_hash != None :
            shares_str = '{0} smbclient -U "{1}%{2}" --pw-nt-hash -g -W {3} -I {4} -L {5} 2>&1 | sed -e "/Reconnecting/ {{ N; d; }}" | grep -P "\|" | cut -d "|" -f 2'
            get_shares_str = shares_str.format(timeout_str, login, nt_hash, domain, ip, ip)
        else:
            shares_str = '{0} smbclient -N -U "{1}" -g -W {2} -I {3} -L {4} 2>&1 | sed -e "/Reconnecting/ {{ N; d; }}" | grep -P "\|" | cut -d "|" -f 2'
            get_shares_str = shares_str.format(timeout_str, login, domain, ip, ip)

        output = check_output(get_shares_str, shell=True).decode(self.parser.inp_encoding)
        tmp = output.replace('\x00','').strip()
        res = [line for line in tmp.split('\n') if line.strip() != '']

        return res

    def nmap_enum_smb_shares(self, ips):
        nmap_cmd_tmpl = 'nmap --host-timeout {1} -n -sT --script smb-enum-shares.nse -p 139,445 {0}'
        nmap_cmd = nmap_cmd_tmpl.format(ips, self.cmd_timeout)
        output = check_output(nmap_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)
        if 'due to host timeout' in output:
            print('    [i] Skipping several hosts due to host timeout. Set correct cmd_timeout_in_sec in default.cfg')
        # Convert multiline for comfortable GREPpint.
        res = {} # {IP : {share1 : Rights, share2: Rights} }
        res1 = output.replace('\n|     ', ' §§§ ')
        res2 = res1.replace('\n|_    ', ' §§§ ')
        res3 = re.findall(r'\|   \\.*', res2)


        if len(res3) == 0:
            return([])

        res4 = ''

        # NT_STATUS_ACCESS_DENIED -> no rights
        for s in res3:
            if 'NT_STATUS_ACCESS_DENIED' in s:
                # GREP IP
                g1 = re.search(r'(?<=\\\\).*?(?=\\)', s)
                re_ip = ''
                if g1 != None:
                    re_ip = g1.group(0)
                # GREP sharename
                g2 = re.search(r'(?<=\\\\).*?(?=:  §§§)', s)
                re_share_tmp = ''
                if g2 != None:
                    re_share_tmp = g2.group(0)
                g3 = re.search(r'(?<=\\).*', re_share_tmp)
                re_share = ''
                if g3 != None:
                    re_share = g3.group(0)

                if re_ip not in res.keys():
                    res[re_ip] = {}
                res[re_ip][re_share] = self.right_no
            else:
                res4 += s + '\n'


        # Each line now is like:
        #|   \\192.168.1.108\Recordings:  §§§ Type: STYPE_DISKTREE §§§ Comment: System default share §§§ Users: 0 §§§ Max Users: <unlimited> §§§ Path: C:\share\CACHEDEV1_DATA\Recordings §§§ Anonymous access: <none> §§§ Current user access: <none>
        for s in res4.strip().split('\n'):
            # GREP IP
            g1 = re.search(r'(?<=\\\\).*?(?=\\)', s)
            re_ip = ''
            if g1 != None:
                re_ip = g1.group(0)

            # GREP sharename
            g2 = re.search(r'(?<=\\\\).*?(?=:  §§§)', s)
            re_share_tmp = ''
            if g2 != None:
                re_share_tmp = g2.group(0)

            g3 = re.search(r'(?<=\\).*', re_share_tmp)
            re_share = ''
            if g3 != None:
                re_share = g3.group(0)

            # GREP rights
            g4 = re.search(r'(?<=Anonymous access: ).*(?= §§§)', s)
            re_rights_anon = ''
            if g4 != None:
                re_rights_anon = g4.group(0)
            g5 = re.search(r'(?<=Current user access: ).*(?=$)', s)
            re_rights_curr_user = ''
            if g5 != None:
                re_rights_curr_user = g5.group(0)

            re_rights = self.right_no
            if re_rights_anon != '<none>':
                if re_rights_anon == 'READ/WRITE':
                    re_rights = self.right_rw
                elif re_rights_anon == 'WRITE':
                    re_rights = self.right_write
                elif re_rights_anon == 'READ':
                    re_rights = self.right_read
            else:
                if re_rights_curr_user == 'READ/WRITE':
                    re_rights = self.right_rw
                elif re_rights_curr_user == 'WRITE':
                    re_rights = self.right_write
                elif re_rights_curr_user == 'READ':
                    re_rights = self.right_read

            if re_ip not in res.keys():
                res[re_ip] = {}
            res[re_ip][re_share] = re_rights

        return(res)



    def nmap_enum_nfs_shares(self, ip): # returns { 'share' : ['CIDR', right-undef] }
        nmap_cmd_tmpl = 'nmap --host-timeout {1} -n -sT --script nfs-showmount.nse -p 111,2049 {0} | grep "|" | grep "/" | replace "|_" "| "'


        nmap_cmd = nmap_cmd_tmpl.format(ip, self.cmd_timeout)
        output = check_output(nmap_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)

        res = None

        for line in output.split('\n'):
            net = ''
            mnt = ''
            g = None
            g = re.search(r'(?<=\s)[^\s]*?$', line)

            if g != None:
                net = g.group(0)
                g2 = None
                g2 = re.search(r'(?<=^\|   ).*(?=\s$)', line.replace(net, ''))
                if g2 != None:
                    mnt = g2.group(0)
                    if res == None:
                        res = {}
                    res[mnt.strip()] = [net.strip(), self.right_undef]

        return(res)


    def nmap_get_nfs_shares_rights(self, nmap_rights):
        nmap_rights

        nmap_cmd_tmpl = 'nmap --host-timeout {1} -n -sT --script nfs-ls.nse -p 111,2049 {0} | grep -E "Volume|access" || true'
        for ip in nmap_rights:
            nmap_cmd = nmap_cmd_tmpl.format(ip, self.cmd_timeout)
            output = check_output(nmap_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding).replace('| nfs-ls: ', '| ').replace('\n|   access:', '§§§').replace('| Volume ','')

            for line in output.split('\n'): # each line is like: /srv/nfsroot space§§§ Read Lookup Modify Extend Delete NoExecute
                g1 = None
                g1 = re.search(r'^.*(?=§§§)', line)
                if g1 != None:
                    sharename = g1.group(0)
                    g2 = None
                    g2 = re.search(r'§§§ Read ', line)
                    if g2 != None:
                        if sharename in nmap_rights[ip]:
                            nmap_rights[ip][sharename][1] = self.right_read
                    g3 = None
                    g3 = re.search(r' Modify ', line)
                    if g3 != None:
                        if sharename in nmap_rights[ip]:
                            if g2 != None:
                                nmap_rights[ip][sharename][1] = self.right_rw
                            else:
                                nmap_rights[ip][sharename][1] = self.right_write
                    if g2 == None and g3 == None:
                        if sharename in nmap_rights[ip]:
                            nmap_rights[ip][sharename][1] = self.right_no

                # add else? when new share found by nfs-ls.nse

        return(nmap_rights)


    #masscan scan 139 and 445 ports, returns list[hosts]
    def masscan_scan_smb_hosts(self, ips, inp_file=None):
        masscan_cmd = ''
        if inp_file != None:
            masscan_cmd = 'masscan --randomize-hosts --rate 5000 --wait 5 -p 139,445 -iL {0} -oG - 2>&1 | grep -E "445/open|139/open|137/open/" | cut -d " " -f 2 | sort | uniq'.format(inp_file)
        else:
            masscan_cmd = 'masscan --randomize-hosts --rate 5000 --wait 5 -p 139,445 {0} -oG - 2>&1 | grep -E "445/open|139/open|137/open/" | cut -d " " -f 2 | sort | uniq'.format(ips)

        output = check_output(masscan_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)

        # Check bad input IP
        if 'bad' in output and 'range' in output:
            res = re.search(r'(?<=ERROR: ).*(?=$)', output)
            if res != None:
                res = res.group(0)
            if res == '':
                print('[x] Warning! Bad input.')
                exit()
            else:
                print('[x] Warning: ' + res)
                exit()
        hosts_with_smb = output.strip().split('\n')
        if len(hosts_with_smb) == 1 and hosts_with_smb[0] == '':
            hosts_with_smb = []
        return hosts_with_smb

    #masscan scan 139 and 445 ports, returns list[hosts]
    def masscan_scan_nfs_hosts(self, ips, inp_file=None):
        masscan_cmd = ''
        if inp_file != None:
            masscan_cmd = 'masscan --randomize-hosts --rate 5000 --wait 5 -p 111 -iL {0} -oG - 2>&1 | grep -E "111/open" | cut -d " " -f 2 | sort | uniq'.format(inp_file)
        else:
            masscan_cmd = 'masscan --randomize-hosts --rate 5000 --wait 5 -p 111 {0} -oG - 2>&1 | grep -E "111/open" | cut -d " " -f 2 | sort | uniq'.format(ips)

        output = check_output(masscan_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)

        # Check bad input IP
        if 'bad' in output and 'range' in output:
            res = re.search(r'(?<=ERROR: ).*(?=$)', output)
            if res != None:
                res = res.group(0)
            if res == '':
                print('[x] Warning! Bad input.')
                exit()
            else:
                print('[x] Warning: ' + res)
                exit()
        hosts_with_nfs = output.strip().split('\n')
        if len(hosts_with_nfs) == 1 and hosts_with_nfs[0] == '':
            hosts_with_nfs = []
        return hosts_with_nfs

    # Nmap scan 139 and 445 ports, returns list[hosts]
    def nmap_scan_smb_hosts(self, ips, inp_file=None):
        nmap_cmd = ''
        if inp_file != None:
            nmap_cmd = 'nmap -n -p 139,445 -oG - --host-timeout {1} -iL {0} | grep -E "445/open|139/open" | cut -d " " -f 2'.format(inp_file, self.cmd_timeout)
        else:
            nmap_cmd = 'nmap -n -p 139,445 -oG - --host-timeout {1} {0} | grep -E "445/open|139/open" | cut -d " " -f 2'.format(ips, self.cmd_timeout)

        output = check_output(nmap_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)

        # Check bad input IP
        if 'No targets were specified' in output:
            res = re.search(r'(?<=^).*(?=\nWARNING)', output)
            if res != None:
                res = res.group(0)
            if res == '':
                print('[x] Warning! Bad input.')
                exit()
            else:
                print('[x] Warning! ' + res)
                exit()
        hosts_with_smb = output.strip().split('\n')
        if len(hosts_with_smb) == 1 and hosts_with_smb[0] == '':
            hosts_with_smb = []
        return hosts_with_smb

    # Nmap scan 111 and 2049 ports, returns list[hosts]
    def nmap_scan_nfs_hosts(self, ips, inp_file=None):
        nmap_cmd = ''
        if inp_file != None:
            nmap_cmd = 'nmap -n -p 111,2049 -oG - --host-timeout {1} -iL {0} | grep -E "111/open|2049/open" | cut -d " " -f 2'.format(inp_file, self.cmd_timeout)
        else:
            nmap_cmd = 'nmap -n -p 111,2049 -oG - --host-timeout {1} {0} | grep -E "111/open|2049/open" | cut -d " " -f 2'.format(ips, self.cmd_timeout)

        output = check_output(nmap_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)

        # Check bad input IP
        if 'No targets were specified' in output:
            res = re.search(r'(?<=^).*(?=\nWARNING)', output)
            if res != None:
                res = res.group(0)
            if res == '':
                print('[x] Warning! Bad input.')
                exit()
            else:
                print('[x] Warning! ' + res)
                exit()
        hosts_with_smb = output.strip().split('\n')
        if len(hosts_with_smb) == 1 and hosts_with_smb[0] == '':
            hosts_with_smb = []
        return hosts_with_smb

    # Request NETBIOS name via nmblookup
    def request_nbt_name(self, ip):
        # timeout --preserve-status 1 nmblookup -A 192.168.1.108 | grep '<00> -         ' | cut -f 2 | cut -d ' ' -f 1
        # nmblookup_cmd = 'timeout --preserve-status 1 nmblookup -A {0} || true | grep "<00> -         " | cut -f 2 | cut -d " " -f 1'.format(ip)
        nmblookup_cmd = 'timeout --preserve-status {0} nmblookup -A {1} || true'.format(self.cmd_timeout, ip)
        output = check_output(nmblookup_cmd, shell=True, stderr=STDOUT).decode(self.parser.inp_encoding)
        line = re.search('.*<00> -         .*', output)
        if line == None:
            return('')
        res = re.search('([^\s]*)(\s*)(?=<00>)', line.group(0))
        return(res.group(0).strip() if res != None else '')

    # TODO: check privs without writing file to share (at least for password auth)
    # smbcacls doesn't work with --pw-nt-hash. I reported a bug, but until it is unfixed we use smbclient to get privs.
    def smbcacls_check_privs(self, ip, share, nt_hash=None, password=None, domain='.', login="Guest"):
        #smbcacls -U 'Guest%' '//192.168.1.108/Public' ''
        chk_privs_cmd_tmpl = ''
        result_right = self.right_undef
        # Anonymous privs
        if password == None and nt_hash == None:
            chk_privs_cmd_tmpl = 'timeout --preserve-status {0} smbcacls -W {1} --no-pass -U "{2}" "//{3}/{4}" ""'
            chk_privs_cmd = chk_privs_cmd_tmpl.format(self.cmd_timeout, domain, login, ip, share)

            output = check_output(chk_privs_cmd, shell=True).decode(self.parser.inp_encoding)
            tmp = output.replace('\x00','').strip()

            result_right = re.search('([^\s]*)(\s*)(?=<00>)', tmp)

        # Password auth
        elif password != None:
            chk_privs_cmd_tmpl = 'timeout --preserve-status {0}  smbcacls -U "{0}%{1}" "//{2}/{3}" ""'
            chk_privs_cmd = chk_privs_cmd_tmpl.format(self.cmd_timeout, login, password, domain, ip, share)
        # Hash auth
        elif nt_hash != None:
            a = ''
            # TODO: PTH check
        return(result_right)


if __name__ == '__main__':
    main = Program()
    try:
        main.unmout_share()
        main.work()
    except KeyboardInterrupt:
        print('\nUnmounting shares...')
        main.unmout_share()
        print('Done.')
