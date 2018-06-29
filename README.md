# Samba, NFS shares spider and grepper
ShareSearch tool goes through hosts with SMB, NFS, checking credentials,
looking for interesting stuff and greping sensitive data in it. WARNING! Alfa version, a lot of bugs and spaghetti code.

## Install
    pip3 install -r requirements.txt
    sudo apt-get install cifs-utils

## Usage
    python3 sharesearch.py [options] DOMAIN/login:password HOSTS_CIDR
    python3 sharesearch.py [options] WORKGROUP/login:LM:NT HOSTS_CIDR

    python3 sharesearch.py -p all -w -v -H hosts.lst -C creds.lst
    python3 sharesearch.py -s --share-num 2 --grep -i prev_share_results.csv 192.168.1.62

### Check credentials:
![Sharesearch usage. Check creds.](https://image.ibb.co/i5GNpy/Selection_290.jpg)

### Grep stuff:
![Sharesearch usage. Grep files.](https://image.ibb.co/m2yDwd/Selection_291.jpg)



## Configuration:
You can configure sharesearch in default.cfg. 

## Lists
<pre>
<b>hostlist.lst</b> => CIDR ranges or hosts
<b>creds.lst</b> => списки учетных записей
</pre>

## Flags
<pre>
<b>--version</b>  =>  show program's version number and exit
<b>-h, --help</b>  =>  show this help message and exit
</pre>

### General Options
<pre>
<b>-i FILE, --import=FILE</b>  =>  Import previous csv-results and print them.
<b>-H FILE, --hosts=FILE</b>  =>  Get target hosts from input file.
<b>-m, --masscan</b>  =>  Use masscan instead of nmap at initial 445, 139 port scan.
<b>-e, --exist</b>  =>  Declare all input (-H) hosts containing SMB shares and skip init port scan. Ranges will be removed.
<b>-C FILE, --creds=FILE</b>  =>  Get credentials from input file.
<b>-p [r/rw/w/no/all], --perms=[r/rw/w/no/all]</b>  =>  Shares with what permissions do we need (default r) [r/rw/w/no/all]
<b>-w, --check-write</b>  =>  Check write permissions trying to upload file.
<b>-v, --verbose</b>  =>  Be verbose. Print all findings to STDOUT.
</pre>

### Share Spider Options
Options for spidering files in shares. You can manage files to spider in default.cfg
<pre>
<b>-s, --spider</b>  =>  Spider interesting files in all shares.
<b>-n SHARE_NUM, --share-num=SHARE_NUM</b>  =>  Shares numbers in imported result list to spider ([,] as delimiter, [0/a/all] for "all").
<b>-d MAX_DEPTH, --depth=MAX_DEPTH</b>  =>  Maximum depth level of recursive spidering (default 5).
<b>-f, --force</b>  =>  Spider everyting in every share, even if it is already spidered. By default we also skip parsing whole "ADMIN$" and "C$/Windows" shares to speed up (but we look for SAM, SYSTEM, hosts files.).
<b>-S FILE, --spider-print=FILE</b>  =>  Print imported Spider results with highlighting.
<b>-t THREADS, --threads=THREADS</b>  =>  TODO: Number of threads while spidering (default 1).
</pre>

### File Grep Options
Options for grep strings in files found by spider. By default it doesn't grep strings in files after spidering shares. You can manage regular expressions list in default.cfg
<pre>
<b>-g, --grep</b>  =>  Grep previously spidered interesting files.
<b>-k MAX_FILE_SIZE, --kb-grep-size=MAX_FILE_SIZE</b>  =>  Maximum filesize in KB for grep (default 200).
<b>-G FILE, --grep-print=FILE</b>  =>  Print imported Grep results with highlighting.
</pre>

## TODO
* Download specified file
* Validate imported csv file
* Add custom regexp
* Add flag for grep how many lines to show before and after match
* Multi threading

## Author
**nikallass**
<br>E-mail: <nikallass@yandex.ru>
<br>Telegram: [@is_man](https://t.me/is_man)
