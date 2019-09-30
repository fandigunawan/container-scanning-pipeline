//Can run groovy code outside of pipeline
//Need to get ISO Time to use for storing artifacts
DATETIME_TAG = java.time.LocalDateTime.now()
DATETIME_TAG = DATETIME_TAG.toString().replaceAll(":", "")

//This is needed for JSON output step
import groovy.json.JsonOutput
import groovy.json.JsonSlurper

//variables to store version information in
anchoreVersion = '{}'
openScapVersion = '{}'
twistLockVersion = '{"version": "19.0.317"}'


// Start of pipeline
pipeline {
  agent { label 'master' }

  environment {
    NEXUS_SERVER = credentials('NexusServerAddress')
    S3_REPORT_BUCKET = 'dsop-pipeline-artifacts'
    S3_HTML_LINK = "https://s3-us-gov-west-1.amazonaws.com/dsop-pipeline-artifacts/"
    OSCAP_NODE = credentials('OpenSCAPNode')

  }  // environment

  parameters {

    choice(choices : ['Test','Production'],
          description: "Is this a test run or for actual production?",
          name: 'testOrProduction')

    choice(choices : ['All','OpenSCAP','Twistlock','Anchore'],
          description: "Which tools to run?",
          name: 'toolsToRun')

    string(defaultValue: "",
            name: 'REPO_NAME',
            description: "Name of repo to be used by Docker, Nexus and all Scanning tools")

     string(defaultValue: "latest",
            name: 'IMAGE_TAG',
            description: "Image tag to be used by Docker, Nexus and all Scanning tools")

    } // parameters

  stages {

    stage('Finish initializing environment') {
      steps {
        script {

          def repo_image_only = REPO_NAME.split("/").last()

          if (testOrProduction == "Production") {
            //ROOT = "container-scan-reports/${repo_image_only}"
            ROOT = "container-scan-reports/${REPO_NAME}"
          } else {
            //ROOT = "testing/container-scan-reports/${repo_image_only}"
            ROOT = "testing/container-scan-reports/${REPO_NAME}"
          }
          echo "ROOT=${ROOT}"

          ROOT_FOR_REPO_IMAGE = "${ROOT}/${IMAGE_TAG}"
          BASIC_PATH_FOR_DATA = "${ROOT_FOR_REPO_IMAGE}/${SPECIFIC_FOLDER_FOR_RUN}"

          echo "TESTING PYTHONS"
          sh "rm /tmp/hello.py"
          sh "rm /tmp/hello.py.1"
          sh "rm /tmp/hello.py.2"
          sh "wget https://dccscr.dsop.io/dsop/container-scanning-pipeline/raw/061f57604a8c4d9ef2fc70dac01105a3c1347037/hello.py /tmp/hello.py"
          sh "/opt/rh/rh-python36/root/bin/python /tmp/hello.py"


        } //script
      } // steps
    } // stage Finish initializing environment
  } // stages
} // pipeline
