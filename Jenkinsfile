//Can run groovy code outside of pipeline
//Need to get ISO Time to use for storing artifacts
DATETIME_TAG = java.time.LocalDateTime.now()
DATETIME_TAG = DATETIME_TAG.toString().replaceAll(":", "")

//This is needed for JSON output step
import groovy.json.JsonOutput
import groovy.json.JsonSlurper

//variables to store version information in
json_documentation = ""
anchoreVersion = '{}'
openScapVersion = '{}'
twistLockVersion = '{}'


// Example Declarative Pipeline with Anchore Scans
pipeline {
  agent { label 'master' }

  environment {
    NEXUS_SERVER = 'nexus-docker.52.61.140.4.nip.io'
    S3_REPORT_BUCKET = 'dsop-pipeline-artifacts'
    REMOTE_HOST = 'ec2-52-222-64-188.us-gov-west-1.compute.amazonaws.com'
  }  // environment

  parameters { choice(choices : 'All\nOpenSCAP\nTwistlock\nAnchore',
    description: "Which tools to run?", name: 'toolsToRun')

    string(defaultValue: "up/ubi7-hardened-dev", name: 'REPO_NAME',
     description: "Name of repo to be used by Docker, Nexus and all Scanning tools")

     string(defaultValue: "latest", name: 'IMAGE_TAG',
      description: "Image tag to be used by Docker, Nexus and all Scanning tools")

     string(defaultValue: "RedHat", name: 'VENDOR_PRODUCT',
      description: "What vendor is being scanned")

    } // parameters

  stages {

    stage('Pull from Staging') {
      //agent { label 'docker' }
      steps {
        echo "Pushing ${REPO_NAME}:${IMAGE_TAG} to Nexus Staging"
        echo "Artifact path is   s3://${S3_REPORT_BUCKET}/${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}"

        //TODO Test docker on agent eventually
        /*withDockerRegistry([url: '${env.NEXUS_SERVER}', credentialsId: '${env.NEXUS_USERNAME}/${env.NEXUS_PASSWORD}']) {
          sh "docker push ${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}"
        }*/
      }
    }

    stage('Run tools in parallel') {
      parallel {
        stage('OpenSCAP Config') {
          when {
            anyOf {
              environment name: "toolsToRun", value: "All"
              environment name: "toolsToRun", value: "OpenSCAP"
            } // anyOf
          } // when

          steps {
            echo 'OpenSCAP Compliance Scan'
            script {
              def remote = [:]
              remote.name = "node"
              remote.host = "${env.REMOTE_HOST}"
              remote.allowAnyHosts = true
              openscap_artifact_path = "s3://${S3_REPORT_BUCKET}/${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}/openscap/"

              node {
                withCredentials([sshUserPrivateKey(credentialsId: 'oscap', keyFileVariable: 'identity', usernameVariable: 'userName')]) {
                  image_full_path = "${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}"
                  remote.user = userName
                  remote.identityFile = identity
                  stage('OpenSCAP Scan') {

                    withCredentials([usernamePassword(credentialsId: 'Nexus', usernameVariable: 'NEXUS_USERNAME', passwordVariable: 'NEXUS_PASSWORD')]) {
                      sshCommand remote: remote, command: "sudo docker login -u ${NEXUS_USERNAME} -p '${NEXUS_PASSWORD}' ${NEXUS_SERVER}"
                    }

                    //grab version and parse
                    openScapVersion = sshCommand remote: remote, command: "oscap -V"

                    sshCommand remote: remote, command: "sudo docker pull ${image_full_path}"
                    sshCommand remote: remote, command: "sudo oscap-docker image ${image_full_path} xccdf eval --profile xccdf_org.ssgproject.content_profile_stig-rhel7-disa --report /tmp/report.html /usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml"
                    sshCommand remote: remote, command: "sudo oscap-docker image-cve ${image_full_path} --report /tmp/report-cve.html"
                    sshCommand remote: remote, command: "/usr/sbin/aws s3 cp /tmp/report-cve.html ${openscap_artifact_path}report-cve.html"
                    sshCommand remote: remote, command: "/usr/sbin/aws s3 cp /tmp/report.html ${openscap_artifact_path}report.html"
                    sshGet remote: remote, from: "/tmp/report.html", into: "/var/lib/jenkins/jobs/${env.JOB_NAME}/builds/${env.BUILD_NUMBER}/openscap-compliance-report.html", override: true
                    sshGet remote: remote, from: "/tmp/report-cve.html", into: "/var/lib/jenkins/jobs/${env.JOB_NAME}/builds/${env.BUILD_NUMBER}/openscap-cve-report.html", override: true
                    publishHTML([alwaysLinkToLastBuild: false, keepAll: false, reportDir: "/var/lib/jenkins/jobs/${env.JOB_NAME}/builds/${env.BUILD_NUMBER}", reportFiles: 'openscap-compliance-report.html', reportName: "OpenSCAP Compliance Report", reportTitles: "OpenSCAP Compliance Report"])
                    publishHTML([alwaysLinkToLastBuild: false, keepAll: false, reportDir: "/var/lib/jenkins/jobs/${env.JOB_NAME}/builds/${env.BUILD_NUMBER}", reportFiles: 'openscap-cve-report.html', reportName: "OpenSCAP Vulnerability Report", reportTitles: "OpenSCAP Vulnerability Report"])
                    //archiveArtifacts "/var/lib/jenkins/jobs/${env.JOB_NAME}/builds/${env.BUILD_NUMBER}/openscap-compliance-report.html"
                  } // script
                } // stage
              } // withCredentials
            } //node
          } // steps
        } // stage

        stage('Twistlock Scan') {
          environment {
            TWISTLOCK_SERVER = 'https://twistlock-console-twistlock.us-gov-west-1.compute.internal'
          }  // environment

          when {
            anyOf {
              environment name: "toolsToRun", value: "All"
              environment name: "toolsToRun", value: "Twistlock"
            } // anyOf
          } // when

          steps {
            echo 'Twistlock Compliance Scan'
            // Using the OpenScap node to overcome docker inside docker limitations,
            // this may use a dedicated node eventually, or be refactored to follow best practice TBD
            script {
              def remote = [:]
              remote.name = "node"
              remote.host = "${env.REMOTE_HOST}"
              remote.allowAnyHosts = true
              twistlock_artifact_path = "s3://${S3_REPORT_BUCKET}/${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}/twistlock/"

              node {
                    // using the oscap user, this is temporary
                withCredentials([sshUserPrivateKey(credentialsId: 'oscap', keyFileVariable: 'identity', usernameVariable: 'userName')]) {
                  remote.user = userName
                  remote.identityFile = identity
                  stage('SSH to Twistlock Node') {
                    // Start the container, import the TwistCLI binary, scan image
                    withCredentials([usernamePassword(credentialsId: 'TwistLock', usernameVariable: 'TWISTLOCK_USERNAME', passwordVariable: 'TWISTLOCK_PASSWORD')]) {
                        sshCommand remote: remote, command: "sudo curl -k -ssl -u ${TWISTLOCK_USERNAME}:'${TWISTLOCK_PASSWORD}' ${TWISTLOCK_SERVER}/api/v1/util/twistcli -o twistcli && sudo chmod +x ./twistcli && sudo ./twistcli images scan ${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG} --user ${TWISTLOCK_USERNAME} --password '${TWISTLOCK_PASSWORD}' --address ${TWISTLOCK_SERVER} --details ${REPO_NAME}:${IMAGE_TAG}"
                        // get version
                        twistLockVersion = sshCommand remote: remote, command: "echo 'Need TODO'"

                        // Pull latest report from the twistlock console
    		                sshCommand remote: remote, command: "curl -k -s -u ${TWISTLOCK_USERNAME}:'${TWISTLOCK_PASSWORD}' -H 'Content-Type: application/json' -X GET '${TWISTLOCK_SERVER}/api/v1/scans?search=${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}&limit=1&reverse=true&type=twistcli' | python -m json.tool | /usr/sbin/aws s3 cp - ${twistlock_artifact_path}/twistlock/${IMAGE_TAG}.json"
                    } // withCredentials
                  } // stage
                } // withCredentials
              } // node
            } // script
          } // steps
        } // stage

        stage('Anchore Scan') {
          when {
            anyOf {
              environment name: "toolsToRun", value: "All"
              environment name: "toolsToRun", value: "Anchore"
            }  // anyOf
          } // when
          steps {
            echo 'Anchore Scan'

            //Below is example command that will be needed in Push to Staging step.
            sh "echo '${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}' > anchore_images"



            anchore bailOnFail: false, bailOnPluginFail: false, name: 'anchore_images'

            script {
              def remote = [:]
              remote.name = "node"
              remote.host = "${env.REMOTE_HOST}"
              remote.allowAnyHosts = true
              anchore_artifact_path = "s3://${S3_REPORT_BUCKET}/${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}/anchore/"

              // get version
              sh(script:"curl -k https://anchore-api.52.61.140.4.nip.io/version > anchor_version.json")
              anchoreVersion = sh(script: "cat anchor_version.json", returnStdout: true)

              echo "${temp}"

              tmp = new JsonSlurper().parseText(anchoreVersion)
              echo "ping 1"
              tmp = null

              node {
              } // Node
            } // script

            //TODO: Push reports to git repo

            // s3Upload consoleLogLevel: 'INFO', dontWaitForConcurrentBuildCompletion: false,
            //    entries: [[bucket: 'dsop-pipeline-artifacts', excludedFile: '', flatten: false,
            //    gzipFiles: false, keepForever: false, managedArtifacts: false, noUploadOnFailure: false,
            //    selectedRegion: 'us-gov-east-1', showDirectlyInBrowser: false,
            //    path: "/var/lib/jenkins/jobs/${env.JOB_NAME}/builds/${env.BUILD_NUMBER}/archive/AnchoreReport.${env.JOB_NAME}_${env.BUILD_NUMBER}",
            //    //sourceFile: "/anchore_gates.json",
            //    includePathPattern:'**/*.json',
            //    storageClass: 'STANDARD', uploadFromSlave: false, useServerSideEncryption: false]], pluginFailureResultConstraint: 'FAILURE',
            //    profileName: '', userMetadata: []

          } // steps
        } // stage

      }// parallel
    } // stage

    stage('Write JSON documentaion') {
      steps {
        script {

          json_documentation = JsonOutput.toJson([timestamp: "${DATETIME_TAG}",
                git: [hash: "${GIT_COMMIT}", branch: "${GIT_BRANCH}"],
                jenkins: [buildTag: "${BUILD_TAG}", buildID: "${BUILD_ID}", buildNumber: "${BUILD_NUMBER}"],
                tools: [anchore: [],
                        openSCAP: [version: "${openScapVersion}"],
                        twistLock: [version: "${twistLockVersion}"] ]])
          // json_documentation.tools.anchore = anchoreVersion
          echo "{$json_documentation}"

          writeFile(file: 'documentation.json', text: json_documentation.toString())


          withAWS(credentials:'s3BucketCredentials') {

              def currentIdent = awsIdentity()

              s3Upload(file: "documentation.json",
                    bucket: "${S3_REPORT_BUCKET}",
                    path:"/${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}/documentation.json")


          }
        } // script



      } // steps
    } // stage

    stage('Push to External Registry (TODO)') {
      environment {
        SIGNING_KEY = credentials('ContainerSigningKey')
        SIGNING_KEY_PASSPHRASE = credentials('ContainerSigningKeyPassphrase')
      }  // environment

      steps {
        //input message: "Push image ${REPO_NAME}:${IMAGE_TAG} to registry?"
        echo 'Pushing to Registry'
        sh "echo 'My very cool container' > sometext.txt"
        sh "g=\$(mktemp -d) && f=\$(mktemp) && trap \"rm \$f;rm -rf \$g\" EXIT || exit 255;gpg --homedir \$g --import --batch --passphrase ${SIGNING_KEY_PASSPHRASE} ${SIGNING_KEY} ;gpg --detach-sign --homedir \$g -o \$f --armor --yes --batch --passphrase ${SIGNING_KEY_PASSPHRASE} sometext.txt;cat \$f;"
      } // steps
    } // stage


    stage('Clean up Docker artifacts') {
      steps {
        echo 'Cleaning up docker artifacts'
        // this may use a dedicated node eventually, or be refactored to follow best practice TBD
        script {
          def remote = [:]
          remote.name = "node"
          remote.host = "${env.REMOTE_HOST}"
          remote.allowAnyHosts = true
          node {
                // using the oscap user, this is temporary
            withCredentials([sshUserPrivateKey(credentialsId: 'oscap', keyFileVariable: 'identity', usernameVariable: 'userName')]) {
              remote.user = userName
              remote.identityFile = identity
              stage('SSH to worker Node') {
                // clean up all docker artifacts
                sshCommand remote: remote, command: "if [[ \$(sudo docker images -q) ]]; then sudo docker rmi \$(sudo docker images -q) --force; fi && if [[ \$(sudo docker ps -a -q) ]]; then sudo docker rm \$(sudo docker ps -a -q); fi"
	      } // stage
	    } //withCredentials
	  } // node
        } // script
      } // steps
      } // steps
  } // stages
} // pipeline
