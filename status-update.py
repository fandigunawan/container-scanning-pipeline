import gitlab
import sys
import datetime
import os
import wget
import fileinput

# USAGE: python status-update.py sys.argv[0]

dccscr = 'https://dccscr.dsop.io/'
state = sys.argv[1]
build_id = sys.argv[2]
#get image name from jenkins - will need this to determine which project the status report will be sent in gitlab
image_path = sys.argv[3]

def status_update(state, build_id, image_path):
    if state == 'FAILED':
        # file = open("build-status.log", 'a')
        update = 'Status Update {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()), str(state), str(build_id)
        readme = wget.download(image_path)
        with fileinput.FileInput(readme, inplace=True) as file:
            for line in file:
                print(line.replace('^Status Update', update).split())

        return readme

    elif state == 'SUCCESS':
        # file = open("build-status.log", 'a')
        update = 'Status Update {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()), str(state), str(build_id)
        readme = wget.download(image_path)
        with fileinput.FileInput(readme, inplace=True) as file:
            for line in file:
                print(line.replace('^Status Update', update).split())

        return readme

def commit_to_git():
    readme = status_update(state, build_id, image_path)




def cleanup():
    my_dir = os.getcwd()
    os.remove(my_dir + '/README.md')



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