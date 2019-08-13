# Building
<code> docker build . </code>

# Running
1. Need to forward ports for httpd server (tcp 80) and flasp app (tcp 8000)
2. Need to forward environment variable for GITLAB_KEY to access gitlab API

<code> docker run -dit -e GITLAB_KEY=??????? -p 1234:80 -p 8000:8000 image_name </code>


# To Do
1. Add Remediation capability for authenticated user
2. Consider whitelist edgecases