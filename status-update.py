import gitlab
import sys
# import importlib
# importlib.import_module('gitlab-class.py')

dccscr = 'https://dccscr.dsop.io/'
# usage: python status-update.py sys.argv[0]

#get image name from jenkins - will need this to determine which project the status report will be sent in gitlab
imageName = 'from jenkins pipeline'

if sys.argv[0] == 'FAILED':
    print('FAILED')
if sys.argv[0] == 'SUCCESS':
    print('SUCCESS')


def return_auth():
    g1 = gitlab.Gitlab(dccscr, private_token='XQ3yQ7RP9LXSLEAAA9jK')
    return g1


def get_projects():
    g1 = return_auth()
    g1.auth()
    projects = g1.projects.list()
    for project in projects:
        print(project)


# def get_current_proj(imageName):
#     id = 'dccscr/dsop'
# def get_pipeline_count():


# get_projects()