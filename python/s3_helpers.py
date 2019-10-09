#!/usr/bin/python3
from bs4 import BeautifulSoup
from requests import get
import re
import json

# un = os.environ['USERNAME']
# pw = os.environ['PASSWORD']
test_base = "https://dsop-pipeline-artifacts.s3-us-gov-west-1.amazonaws.com/"
trimmed_url = "testing/container-scan-reports/redhat/ubi7/repo_map.html"


def main():
    for item in get_last_n_runs(trimmed_url, 5):
        print(item)


def get_all_runs(url):
    response = get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    header2s = soup.find_all('h2')[0:5]
    for header in header2s:
        run_grp = re.search('Run for (.*) using with tag', header.text)
        run_number = run_grp.group(1)
        links = soup.find('a', attrs={'href': re.compile("_" + re.escape(run_number) + ".*-signature.tar.gz")})
        print(header.text, run_number, links['href'])


def get_last_n_runs(url, num):
    if test_base not in url:
        url = test_base + url
    response = get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    return_list = []

    header2s = soup.find_all('h2')[0:num]
    for header in header2s:
        run_grp = re.search('Run for (.*) using with tag', header.text)
        run_number = run_grp.group(1)
        links = soup.find('a', attrs={'href': re.compile("_" + re.escape(run_number) + ".*-signature.tar.gz")})
        ret = {
            'header': header.text,
            'run_number': run_number,
            'link': links['href']
        }
        return_list.append(ret)

    # print(len(return_list))
    return json.dumps(return_list)


if __name__ == "__main__":
    main()  # with if