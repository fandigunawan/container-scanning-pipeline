//Can run groovy code outside of pipeline
//Need to get ISO Time to use for storing artifacts
DATETIME_TAG = java.time.LocalDateTime.now()
DATETIME_TAG = DATETIME_TAG.toString().replaceAll(":", "")



// Example Declarative Pipeline with Anchore Scans
pipeline {
  agent { label 'master' }

  environment {
    NEXUS_SERVER = 'nexus-docker.52.61.140.4.nip.io'
    S3_REPORT_BUCKET = 's3://dsop-pipeline-artifacts'
    TWISTLOCK_SERVER = 'https://twistlock-console-twistlock.us-gov-west-1.compute.internal'
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
        echo "Artifact path is   ${S3_REPORT_BUCKET}/${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}"

        //TODO Test docker on agent eventually
        /*withDockerRegistry([url: '${env.NEXUS_SERVER}', credentialsId: '${env.NEXUS_USERNAME}/${env.NEXUS_PASSWORD}']) {
          sh "docker push ${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}"
        }*/
      }
    }

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
          node {
            withCredentials([sshUserPrivateKey(credentialsId: 'oscap', keyFileVariable: 'identity', usernameVariable: 'userName')]) {
              openscap_artifact_path = "${S3_REPORT_BUCKET}/${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}/openscap/"
              image_full_path = "${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}"
              remote.user = userName
              remote.identityFile = identity
              stage('OpenSCAP Scan') {

                withCredentials([usernamePassword(credentialsId: 'Nexus', usernameVariable: 'NEXUS_USERNAME', passwordVariable: 'NEXUS_PASSWORD')]) {
                  sshCommand remote: remote, command: "sudo docker login -u ${NEXUS_USERNAME} -p '${NEXUS_PASSWORD}' ${NEXUS_SERVER}"
                }

                sshCommand remote: remote, command: "sudo docker pull ${image_full_path}"
                sshCommand remote: remote, command: "sudo oscap-docker image ${image_full_path} xccdf eval --profile xccdf_org.ssgproject.content_profile_stig-rhel7-disa --report /tmp/report.html /usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml"
                sshCommand remote: remote, command: "sudo oscap-docker image-cve ${image_full_path} --report /tmp/report-cve.html"
                sshCommand remote: remote, command: "/usr/sbin/aws s3 cp /tmp/report-cve.html ${openscap_artifact_path}report-cve.html"
                sshCommand remote: remote, command: "/usr/sbin/aws s3 cp /tmp/report.html ${openscap_artifact_path}report.html"
                sshGet remote: remote, from: "/tmp/report.html", into: "/var/lib/jenkins/jobs/${env.JOB_NAME}/builds/${env.BUILD_NUMBER}/openscap-compliance-report.html", override: true
                sshGet remote: remote, from: "/tmp/report-cve.html", into: "/var/lib/jenkins/jobs/${env.JOB_NAME}/builds/${env.BUILD_NUMBER}/openscap-cve-report.html", override: true
                publishHTML([alwaysLinkToLastBuild: false, keepAll: false, reportDir: "/var/lib/jenkins/jobs/${env.JOB_NAME}/builds/${env.BUILD_NUMBER}", reportFiles: 'openscap-compliance-report.html', reportName: 'OpenSCAP Compliance Report', reportTitles: 'OpenSCAP Compliance Report'])
                publishHTML([alwaysLinkToLastBuild: false, keepAll: false, reportDir: "/var/lib/jenkins/jobs/${env.JOB_NAME}/builds/${env.BUILD_NUMBER}", reportFiles: 'openscap-cve-report.html', reportName: 'OpenSCAP Vulnerability Report', reportTitles: 'OpenSCAP Vulnerability Report'])
                //archiveArtifacts "/var/lib/jenkins/jobs/${env.JOB_NAME}/builds/${env.BUILD_NUMBER}/openscap-compliance-report.html"
              } // script
            } // stage
          } // withCredentials
        } //node
      } // steps
    } // stage

    stage('Twistlock Scan') {
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
          node {
                // using the oscap user, this is temporary
            withCredentials([sshUserPrivateKey(credentialsId: 'oscap', keyFileVariable: 'identity', usernameVariable: 'userName')]) {
              remote.user = userName
              remote.identityFile = identity
              stage('SSH to Twistlock Node') {
                // Start the container, import the TwistCLI binary, scan image
                withCredentials([usernamePassword(credentialsId: 'TwistLock', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {
                  sshCommand remote: remote, command: "sudo curl -k -ssl -u ${USERNAME}:'${PASSWORD}' ${TWISTLOCK_SERVER}/api/v1/util/twistcli -o twistcli && sudo chmod +x ./twistcli && sudo ./twistcli images scan ${REPO_NAME}:${IMAGE_TAG} --user ${USERNAME} --password '${PASSWORD}' --address ${TWISTLOCK_SERVER} --details ${REPO_NAME}:${IMAGE_TAG}"
                }// withCredentials
                // Clean up
                //  Stop or remove the container image if needed..
                // ToDo - Catch, or call from the console, the twistcli scan results, and complile them with the rest of the pipeline
                // Possibly make an API call to /images/scan/id
              } // script
            } // stage
          } // withCredentials
        } //node
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




    stage('Push to External Registry (TODO)') {
      steps {
        //input message: "Push image ${REPO_NAME}:${IMAGE_TAG} to registry?"
        echo 'Pushing to Registry'
      } // steps
    } // stage

  } // stages

} // pipeline
