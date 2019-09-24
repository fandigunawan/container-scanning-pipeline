import json
import os
import requests
import jenkins
import urllib3


api_response = {
  "schemaVersion": 1,
  "label": "Pipeline Status",
  "message": "",
  "color": ""
}

url = 'https://jenkins-jenkins-demo.52.61.140.4.nip.io/' #job/container-scanning-pipeline/job/krafaels_test/api/json?pretty=true
username = 'demo-user'
password = 'Q92%KNzWSwzTn^d^4r'
os.environ.setdefault("PYTHONHTTPSVERIFY", "0")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
server = jenkins.Jenkins(url, username, password)
info = server.get_job_info('container-scanning-pipeline/krafaels_test')

print(info['lastCompletedBuild']['number'])
print(info['lastFailedBuild']['number'])

fail_number = info['lastFailedBuild']['number']
last_complete_number = info['lastCompletedBuild']['number']

if fail_number == last_complete_number:
    api_response['message'] = 'FAILED'
    api_response['color'] = 'red'

else:
    api_response['message'] = 'SUCCESS'
    api_response['color'] = 'green'


print(api_response)