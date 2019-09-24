import gitlab
import sys
import datetime
import os
import wget
import fileinput
from git import Repo

# USAGE: python status-update.py <state> <build_id> <git_repo_path>

dccscr = 'https://dccscr.dsop.io/'
state = sys.argv[1]
build_id = sys.argv[2]
#get image name from jenkins - will need this to determine which project the status report will be sent in gitlab
git_repo_path = sys.argv[3]


def status_update(state, build_id, image_tag):
    if state == 'FAILED':
        # file = open("build-status.log", 'a')
        update = 'Status Update {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()), str(state), str(build_id)
        readme = wget.download(git_repo_path)
        with fileinput.FileInput(readme, inplace=True) as file:
            for line in file:
                print(line.replace('^Status Update', update).split())

        return state

    elif state == 'SUCCESS':
        # file = open("build-status.log", 'a')
        update = 'Status Update {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()), str(state), str(build_id)
        readme = wget.download(git_repo_path)
        with fileinput.FileInput(readme, inplace=True) as file:
            for line in file:
                print(line.replace('^Status Update', update).split())

        return state

#another conditional will follow the previous elif to evaluate var state for 'APPROVAL' and 'REJECTION'

def clone_repo(git_repo_path):
    cloned_repo = git.Git("/repodrop/")


def commit_to_git(git_repo_path):
    try:
        # readme = status_update(state, build_id, git_repo_path)
        repo.git.add("README.md")
        repo.git.commit("Status Update modification")
        origin = repo.remote(name='pipeline-build-status')
        origin.push()
    except:
        print('invalid Git repo path')


def cleanup():
    my_dir = os.getcwd()
    os.remove(my_dir + '/README.md')


print(status_update(state, build_id, git_repo_path))