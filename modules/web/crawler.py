from requests import get

from bs4 import BeautifulSoup

from modules.random_user_agent import random_user_agent
from modules.logger import Logger


def crawl(target_url):
    log = Logger()

    if not target_url.endswith("/"):
        target_url += "/"

    for tries in range(3):
        try:
            reqs = get(
                    target_url, headers={
                            "User-Agent": next(random_user_agent())
                        }
                )
            soup = BeautifulSoup(reqs.text, "html.parser")
        except ConnectionError:
            if tries < 3:
                log.logger(
                    "error",
                    f"Connection error raised, retrying again: {tries}."
                )
                continue
            else:
                log.logger(
                    "error",
                    f"Connection error raised, reached a maximum of 3 tries."
                )
                raise SystemExit

    urls = set()
    for link in soup.find_all("a", href=True):
        url = link["href"]

        if not url.startswith("http"):
            if "#" in url or url is None or url == "":
                continue
            elif url.startswith("./"):
                url = f"{target_url}{url.lstrip('./')}"
            elif url.startswith("/"):
                url = f"{target_url}{url.lstrip('/')}"
            else:
                url = f"{target_url}{url}"

            if url not in urls:
                urls.add(url)
        else:
            if url.startswith(target_url):
                if url not in urls:
                    urls.add(url)

    if len(urls) < 10:
        urls_temp = set() # we need to do this because we get a RuntimeError due to changed size in set during iteration
        for each_url in urls:
            try:
                reqs = get(each_url)
                soup = BeautifulSoup(reqs.text, "html.parser")
            except ConnectionError:
                log.logger(
                    "error",
                    f"Connection error raised on: {each_url}, skipping ..."
                )
                continue
            else:
                for link in soup.find_all("a", href=True):
                    url = link["href"]
                    if url == "" or url is None or "#" in url:
                        continue

                    if not url.startswith("http"):
                        if url.startswith("./"):
                            url = f"{each_url}{url.lstrip('./')}"
                        elif url.startswith("/"):
                            url = f"{each_url}{url.lstrip('/')}"
                        else:
                            url = f"{each_url}{url}"

                        if url not in urls:
                            urls_temp.add(url)
                    else:
                        if url.startswith(each_url):
                            if url not in urls:
                                urls_temp.add(url)
        
        for url in urls_temp:
            urls.add(url)


    return urls
