# Container Scanning Pipeline

A staging area for testing and developing the container scanning pipeline, a declarative Jenkins pipeline.

Note: Master branch still under active development.
      This Jenkinsfile makes use of several Jenkins credentials required to protect authentication into the various tools
      TODO: outline what creds are needed to repeat this pipeline

This pipeline currently does the following (5/24):
*  Checks out the Jenkinsfile located in this repo
*  As a paramater, allows selecting a subset of the tools used to scan (OScap, Anchore, Twistlock), defaults to all
*  As a parameter, requests selection of the vendor name (opensource, redhat, anchore, etc)
*  As a parameter, requests a string as the input for the image to be scanned ie `up/ubi7-stigd`
*  Pulls the docker image to a build server
*  Runs OpenScap, Anchore, and TwistLock against the image in parallel
*  Aggregates all documentation from the selected scanning tools
*  Signs the container manifest with the default gpg key
*  Creates a tar of all reports and an export of the container image
*  Pushes the tar(s) to S3 within its perscribed folder structure
*  Creates a repo map of the reports in json and html
*  Cleans up the docker artifacts pulled from the default nexus registry

Resulting artifacts (currently hosted on s3) include:
*  A repo_map.html that includes the public gpg key used to sign files embedded in the page
*  A json file that will be used to facilitate programmatic and automated repo cloning of images and reports
*  A tar file containing all scanning reports
*  A tar file of the exported container

# Latest Build Status 
[![Build Status](https://jenkins-jenkins-demo.52.61.140.4.nip.io/buildStatus/icon?job=container-scanning-pipeline%2Fkrafaels_test)](https://jenkins-jenkins-demo.52.61.140.4.nip.io/job/container-scanning-pipeline/job/krafaels_test/)
