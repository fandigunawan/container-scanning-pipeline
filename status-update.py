import gitlab
import sys
import datetime

# USAGE: python status-update.py sys.argv[0]

dccscr = 'https://dccscr.dsop.io/'
state = sys.argv[1]
build_id = sys.argv[2]

#get image name from jenkins - will need this to determine which project the status report will be sent in gitlab
imageName = 'from jenkins pipeline'

if state == 'FAILED':
    file = open("build-status.log", 'a')
    print('{:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()), 'Status Update:', str(state), str(build_id), file=file)

if state == 'SUCCESS':
    file = open("build-status.log", 'a')
    print('{:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()), 'Status Update:', str(state), str(build_id), file=file)

# def return_auth():
#     g1 = gitlab.Gitlab(dccscr, private_token='XQ3yQ7RP9LXSLEAAA9jK')
#     return g1
#
#
# def get_projects():
#     g1 = return_auth()
#     g1.auth()
#     projects = g1.projects.list()
#     for project in projects:
#         print(project)


# def get_current_proj(imageName):
#     id = 'dccscr/dsop'
# def get_pipeline_count():


# get_projects()