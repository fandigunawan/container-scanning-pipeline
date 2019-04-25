# Jenkins Demo Pipeline Tutorial
##### From Nothing, to Pipeline in 15 minutes
This tutorial will show you how easy it can be to stand up your own pipeline in Jenkins.
Looking to install Jenkins on OCP and Build a pipeline? Start at Step 1.
Looking to just stand up a new pipeline? Start on Step 2
### Pre-Reqs
 - Pre-dev Environment Only (TODO: Parameterize Links for Flexability)
 - Gitlab Jenkins user w/ ssh keys

### 1. Installation in OCP
#### WIP

### 2. Creating your own Pipeline

1. Install Plugins (Ignore if you did not do step 1.)
```
From Jenkins Dashboard go to Manage Jenkins > Manage Plugins > Available
Install the following plugins:
Anchore Container Scanner
SSH Steps
```
2. Create Openscap Credentials (Ignore if you did not do step 1.):
```
From Jenkins Dashboard go to Credentials > System > Global Credentials > Add Credentials > SSH Username with Private Key
Select the Private Key checkbox and enter the private key for your pre-req made jenkins user from gitlab
Enter username and hit Create
```
3. Configure Anchore (Ignore if you did not do step 1.):
```
From Jenkins Dashboard go to Manage Jenkins > Configure Jenkins > Scroll to Anchore Plugin Config
Enter our anchore url and user/password (Anchore url used for Demo: http://up-anchore-engine-api.anchore.svc:8228/v1)
```
4. Create Jenkins Pipeline
```
From Jenkins Dashboard go to: New Item > New Pipeline (Give it a name)
On the screen for configuration select the 'this build is parameterized' checkbox
Select Add Parameter > String Parameter
Enter IMAGE_TAG for name, and a default value (Demo used: up/ubi7-hardened-dev:latest)
Scroll down to bottom of configuration, and click under Pipeline: Definition: Pipeline from SCM
Enter Repository url and gitlab user (Demo used: git@ec2-52-61-29-205.us-gov-west-1.compute.amazonaws.com:unified-platform/tool-configs.git)
Type Branch name (Demo used: master)
Click Ok to generate the pipeline
