#!/usr/bin/env python3
"""
Capture screenshots from iDRAC7/8.

This code is based on
https://github.com/spotify/moob/blob/master/lib/moob/idrac7.rb
"""


import argparse
import logging
import sys
import time
import urllib.parse
import warnings
from http.cookiejar import CookieJar
from mimetypes import guess_extension

import requests

LOG_FORMAT = "%(asctime)s %(levelname)-5s %(message)s"
USERNAME = "root"
PASSWORD = "calvin"


warnings.filterwarnings("ignore")


class NodeSplitAction(argparse.Action):
    """Helper class to split the nodes by comma."""

    def __call__(self, parser, namespace, values, option_string=None):
        """Split the arguments the custom way."""
        hosts = [val.split(",") for val in values]
        host_list = list(map(str.strip, sum(hosts, [])))
        setattr(namespace, self.dest, host_list)


class DracScreenshotClient:
    """The screenshot client class."""

    def __init__(self, endpoint=None, user=None, password=None, outfile=None):
        """Sanitize the class attributes."""
        self.user = user
        self.password = password
        self.endpoint = endpoint
        self.verify = False
        self.jar = CookieJar()
        self.session = requests.session()
        self.st2 = None
        self.outfile = outfile
        self.headers = {
            "Accept-Language": "en-US,en;q=0.8,sv;q=0.6",
            "Accept-Encoding": "gzip,deflate,sdch",
        }

    def login(self):
        """Log-in to DRAC."""
        try:
            rsp = self.session.get(
                f"{self.endpoint}login.html",
                headers=self.headers,
                verify=self.verify,
                cookies=self.jar,
            )
            rsp.raise_for_status()
        except Exception as e:
            logging.error(
                "ERROR: Unable to connect to %s, bailing out! (%s)",
                self.endpoint,
                str(e),
            )
            return False

        login_data = {
            "user": self.user,
            "password": self.password,
        }
        rsp = self.session.post(
            f"{self.endpoint}data/login",
            headers=self.headers,
            data=login_data,
            verify=self.verify,
            cookies=self.jar,
        )
        if rsp.status_code != 200:
            logging.error(
                "Unable to post the log-in data for %s. Status code: %d",
                self.endpoint,
                rsp.status_code,
            )
            logging.debug(rsp.text)
            return False

        if "errorMsg" in rsp.text:
            logging.error(
                "Unable to log-in to %s: an errorMsg is present: %s",
                self.endpoint,
                rsp.text,
            )
            return False

        if "forwardUrl" not in rsp.text:
            logging.error(
                "Unable to log-in to %s. forwardUrl is not present: %s",
                self.endpoint,
                rsp.text,
            )
            return False

        forwardUrl = (
            rsp.text.split("<forwardUrl>")[1]
            .split("</forwardUrl>")[0]
            .replace("defaultCred", "index")
        )
        # Special Token #2. Just kidding. A token that must be added to subsequent requests.
        self.st2 = urllib.parse.urlparse(forwardUrl).query.split("ST2=")[1]

        rsp = self.session.get(
            f"{self.endpoint}{forwardUrl}",
            headers=self.headers,
            verify=self.verify,
            cookies=self.jar,
        )
        if rsp.status_code != 200:
            logging.warning(
                "Unable to follow the index redirect on %s. Status code: %d",
                self.endpoint,
                rsp.status_code,
            )
        return True

    def logout(self):
        """Log-out from DRAC."""
        rsp = self.session.get(
            f"{self.endpoint}data/logout",
            verify=self.verify,
            cookies=self.jar,
        )
        if rsp.status_code != 200:
            logging.warning(
                "Unable to log-out off %s. Status code: %d",
                self.endpoint,
                rsp.status_code,
            )

    def get_screenshot(self):
        """Do the deed."""
        ts = round(time.time() * 1000)
        try:
            rsp = self.session.get(
                f"{self.endpoint}data?get=consolepreview[auto%20{ts}]",
                verify=self.verify,
                cookies=self.jar,
                headers={"St2": self.st2},
            )
            rsp.raise_for_status()
        except Exception as e:
            logging.error(
                "ERROR: Unable to connect to %s, bailing out! (%s)",
                self.endpoint,
                str(e),
            )
            return

        rsp = self.session.get(
            f"{self.endpoint}capconsole/scapture0.png?{ts}",
            verify=self.verify,
            cookies=self.jar,
            headers={"St2": self.st2},
        )
        try:
            rsp.raise_for_status()
        except Exception as e:
            logging.error(
                "ERROR: Unable to capture screenshot for %s, skipping! (%s)",
                self.endpoint,
                str(e),
            )
            return
        content_type = rsp.headers["Content-Type"]
        ext = guess_extension(rsp.headers["Content-Type"].partition(";")[0].strip())
        outfile = f"{self.outfile}{ext}"
        logging.info(
            "Screenshot of %s result: response content-type: %s, file name=%s",
            self.endpoint,
            content_type,
            outfile,
        )
        with open(outfile, "wb") as shotfile:
            shotfile.write(rsp.content)


def parse_args():
    """Parse program arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        dest="debug",
        help='Increase logging verbosity for debug purposes. Default: "%(default)s".',
    )
    parser.add_argument(
        "--nodes",
        required=True,
        nargs="+",
        action=NodeSplitAction,
        dest="nodes",
        help="Comma delimited list of servers (FQDN or IPs) for screenshot capture.",
    )
    parser.add_argument(
        "--user",
        default=USERNAME,
        dest="user",
        help="Drac username. Default: %(default)s.",
    )
    parser.add_argument(
        "--password",
        default=PASSWORD,
        dest="password",
        help="Drac password. Default: %(default)s.",
    )
    parser.add_argument(
        "--dest-path",
        dest="dest_path",
        default="screenshots/screenshot_{node}",
        help="Path to the directory where to store the screenshots to. Default: %(default)s",
    )
    return parser.parse_args()


def main():
    """Run the main job."""
    args = parse_args()
    logging.basicConfig(format=LOG_FORMAT, stream=sys.stdout, level=logging.INFO)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    for node in args.nodes:
        logging.info("Capturing data for %s", node)
        drac = DracScreenshotClient(
            user=args.user,
            password=args.password,
            endpoint=f"https://{node}/",
            outfile=args.dest_path.format(node=node),
        )
        if not drac.login():
            continue
        drac.get_screenshot()
        drac.logout()


if __name__ == "__main__":
    main()
