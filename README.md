# Python iDRAC7/8 screenshot capture tool

## TL;DR

So you want to capture a screenshot of your running server? Just replace the username/password with the ones you actually use and run this command.

(You have replaced the default password, have you? **Have you?**)

```
# You may need to create a Python virtualenv first. Or use Poetry. We will add support of Poetry soonish.
pip install -r requirements.txt
./drac-screenshot.py --user root --password calvin --nodes 2001:db8:de11::11,2001:db8:de11::12
```

The screenshots will be stored in the `screenshots/` directory.

## Get help

Run the command with `-h`. There's not much more to say. You can change the output directory and run the script in debug mode, if you want to.

```
$ ./drac-screenshot.py -h
usage: drac-screenshot.py [-h] [-d] --nodes NODES [NODES ...] [--user USER] [--password PASSWORD] [--dest-path DEST_PATH]

options:
  -h, --help            show this help message and exit
  -d, --debug           Increase logging verbosity for debug purposes. Default: "False".
  --nodes NODES [NODES ...]
                        Comma delimited list of servers (FQDN or IPs) for screenshot capture.
  --user USER           Drac username. Default: root.
  --password PASSWORD   Drac password. Default: calvin.
  --dest-path DEST_PATH
                        Path to the directory where to store the screenshots to. Default: screenshots/screenshot_{node}
```

You may include the IP/node name in the screenshot file name by placing `{node}` somewhere within the `--dest-path` argument, like the default `screenshots/screenshot_{node}`. Or you may specify something like `screenshots/{node}` to store the files by just their node name + image-type based file extension.

If you specify hostnames instead of IPs, these hostnames will be used in the filenames, instead of the IPs.

The image file extension (like `.png`) is determined automatically, based on the `Content-Type` response header.

## Credits

This work is based on [spotify/moob's idrac7.rb](https://github.com/spotify/moob/blob/master/lib/moob/idrac7.rb).
