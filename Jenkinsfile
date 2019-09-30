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

    PUBLIC_DOCKER_HOST = "${NEXUS_SERVER}"
    PUBLIC_IMAGE_SHA = ""

    S3_IMAGE_NAME = " "
    S3_IMAGE_LOCATION = " "

    ROOT = " "
    ROOT_FOR_REPO_IMAGE = " "
    SPECIFIC_FOLDER_FOR_RUN = "${DATETIME_TAG}_${BUILD_NUMBER}"
    BASIC_PATH_FOR_DATA = " "

    S3_SIGNATURE_FILENAME = "signature.sig"
    S3_SIGNATURE_LOCATION =  " "
    S3_MANIFEST_NAME = "manifest.json"
    S3_MANIFEST_LOCATION = " "

    S3_DOCUMENTATION_FILENAME = "documentation.json"
    S3_DOCUMENTATION_LOCATION = " "

    S3_TAR_FILENAME = " "
    S3_TAR_LOCATION = " "

    S3_OSCAP_CVE_REPORT = "report-cve.html"
    S3_OSCAP_REPORT = "report.html"
    S3_OSCAP_LOCATION = " "

    S3_TWISTLOCK_REPORT = "${IMAGE_TAG}.json"
    S3_TWISTLOCK_LOCATION = " "

    S3_ANCHORE_GATES_REPORT = "anchore_gates.json"
    S3_ANCHORE_SECURITY_REPORT = "anchore_security.json"
    S3_ANCHORE_LOCATION = " "



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

          S3_SIGNATURE_LOCATION =  "${BASIC_PATH_FOR_DATA}/${S3_SIGNATURE_FILENAME}"
          S3_MANIFEST_LOCATION = "${BASIC_PATH_FOR_DATA}/${S3_MANIFEST_NAME}"

          S3_DOCUMENTATION_LOCATION = "${BASIC_PATH_FOR_DATA}/${S3_DOCUMENTATION_FILENAME}"

          S3_OSCAP_LOCATION = "${BASIC_PATH_FOR_DATA}/openscap/"

          S3_TWISTLOCK_LOCATION = "${BASIC_PATH_FOR_DATA}/twistlock/"

          S3_ANCHORE_LOCATION = "${BASIC_PATH_FOR_DATA}/anchore/"

          S3_IMAGE_NAME = "${repo_image_only}-${IMAGE_TAG}.tar"
          S3_IMAGE_LOCATION = "${BASIC_PATH_FOR_DATA}/${S3_IMAGE_NAME}"
          S3_TAR_FILENAME = "${repo_image_only}-${IMAGE_TAG}-reports-signature.tar.gz"

          S3_TAR_LOCATION = "${BASIC_PATH_FOR_DATA}/${S3_TAR_FILENAME}"
          
          echo "TESTING PYTHONS"
          wget https://dccscr.dsop.io/dsop/container-scanning-pipeline/raw/061f57604a8c4d9ef2fc70dac01105a3c1347037/hello.py /tmp/hello.py
          sh "/opt/rh/rh-python36/root/bin/python /tmp/hello.py"


        } //script
      } // steps
    } // stage Finish initializing environment
  } // stages
} // pipeline
