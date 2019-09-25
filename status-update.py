import gitlab
import git
import sys
import datetime
import os
import wget
import fileinput
from git import Repo

# USAGE: python status-update.py <state> <build_id> <repo>

dccscr = 'https://dccscr.dsop.io/'
state = sys.argv[1]
build_id = sys.argv[2]
# get image name from jenkins - will need this to determine which project the status report will be sent in gitlab
repo = sys.argv[3]


def status_update(state, build_id, repo):
    if state == 'FAILED':
        # file = open("build-status.log", 'a')
        update = 'Status Update {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()), str(state), str(build_id)
        readme = wget.download(repo)
        with fileinput.FileInput(readme, inplace=True) as file:
            for line in file:
                print(line.replace('^Status Update', update).split())

    elif state == 'SUCCESS':
        # file = open("build-status.log", 'a')
        update = 'Status Update {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()), str(state), str(build_id)
        readme = wget.download(repo)
        with fileinput.FileInput(readme, inplace=True) as file:
            for line in file:
                print(line.replace('^Status Update', update).split())


# another conditional will follow the previous elif to evaluate var state for 'APPROVAL' and 'REJECTION'

# first create a separate branch and checkout
def create_branch(repo):
    new_branch = repo.create_head('pipeline-build-status')
    new_branch.checkout()
    return new_branch


# clone branch to local directory
def clone_repo(repo):
    branch = create_branch(repo)
    cloned_repo = git.Git("/repodrop/").clone(branch)

    return cloned_repo


# perform string replacement and then commit and push to branch
def commit_to_git(repo):
    local_copy = clone_repo(repo)
    try:
        status_update(state, build_id, repo)
        local_copy.git.add('README.md')
        local_copy.git.commit("Status Update modification")
        origin = repo.remote(name='pipeline-build-status')
        origin.push()
    except:
        print('invalid Git repo path')

# NOTE:
# According to gitPython documentation it is not recommended to use module to merge branches to master
# pipeline-build-status branch will have updated README.md with status update but how do we merge?
# use input to prompt user for permission to merge branches?
def merge_branch_to_master(repo):
    repo.git.checkout('master')
    repo.git.merge('pipeline-build-status')


# cleanup local repo files
def cleanup():
    my_dir = os.getcwd()
    os.remove(my_dir + '/README.md')


if __name__ == "__main__":
    try:
        commit_to_git(repo)
        merge_branch_to_master(repo)
    except Exception as error:
        print(error)
    finally:
        cleanup()




