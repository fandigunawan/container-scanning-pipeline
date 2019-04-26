// Example Declarative Pipeline with Anchore Scans
pipeline {
  agent { label 'master' }

  environment {
    NEXUS_SERVER = 'nexus-docker.52.61.140.4.nip.io'

  }

  stages {

    stage('Pull from Staging') {
      //agent { label 'docker' }
      steps {
        echo "Pushing ${IMAGE_TAG} to Nexus Staging"

        //TODO Test docker on agent eventually
        /*withDockerRegistry([url: 'nexus-docker.52.61.140.4.nip.io', credentialsId: 'admin/admin123']) {
          sh "docker push nexus-docker.52.61.140.4.nip.io/${IMAGE_TAG}"
        }*/
      }
    }

    stage('OpenSCAP Config') {
      steps {
        echo 'OpenSCAP Compliance Scan'
        script {
          def remote = [:]
          remote.name = "node"
          remote.host = "ec2-52-222-64-188.us-gov-west-1.compute.amazonaws.com"
          remote.allowAnyHosts = true
          node {
            withCredentials([sshUserPrivateKey(credentialsId: 'oscap', keyFileVariable: 'identity', usernameVariable: 'userName')]) {
              remote.user = userName
              remote.identityFile = identity
              stage('OpenSCAP Scan') {
                sshCommand remote: remote, command: "sudo docker login -u admin -p admin123 ${NEXUS_SERVER}"
                sshCommand remote: remote, command: "sudo docker pull nexus-docker.52.61.140.4.nip.io/${IMAGE_TAG}"
                sshCommand remote: remote, command: "sudo oscap-docker image nexus-docker.52.61.140.4.nip.io/${IMAGE_TAG} xccdf eval --profile xccdf_org.ssgproject.content_profile_stig-rhel7-disa --report /tmp/report.html /usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml"
                sshCommand remote: remote, command: "sudo oscap-docker image-cve nexus-docker.52.61.140.4.nip.io/${IMAGE_TAG} --report /tmp/report-cve.html"
                sshCommand remote: remote, command: "/usr/sbin/aws s3 cp /tmp/report-cve.html s3://dsop-pipeline-artifacts/openscap/report-cve.html"
                sshCommand remote: remote, command: "/usr/sbin/aws s3 cp /tmp/report.html s3://dsop-pipeline-artifacts/openscap/report.html"
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
      steps {
        echo 'Twistlock Compliance Scan'
        // Using the OpenScap node to overcome docker inside docker limitations,
        // this may use a dedicated node eventually, or be refactored to follow best practice TBD
        script {
          def remote = [:]
          remote.name = "node"
          remote.host = "ec2-52-222-64-188.us-gov-west-1.compute.amazonaws.com"
          remote.allowAnyHosts = true
          node {
                // using the oscap user, this is temporary
            withCredentials([sshUserPrivateKey(credentialsId: 'oscap', keyFileVariable: 'identity', usernameVariable: 'userName')]) {
              remote.user = userName
              remote.identityFile = identity
              stage('SSH to Twistlock Node') {
                // Start the container, import the TwistCLI binary, scan image
                sshCommand remote: remote, command: "sudo curl -k -ssl -u jenkins-svc:redhat12 https://twistlock-console-twistlock.us-gov-west-1.compute.internal/api/v1/util/twistcli -o twistcli && sudo chmod +x ./twistcli && sudo ./twistcli images scan ${IMAGE_TAG} --user jenkins-svc --password redhat12 --address https://twistlock-console-twistlock.us-gov-west-1.compute.internal --details ${IMAGE_TAG}"
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
      steps {
        echo 'Anchore Scan'

        //Below is example command that will be needed in Push to Staging step.
        sh "echo 'nexus-docker.52.61.140.4.nip.io/${IMAGE_TAG}' > anchore_images"

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
        //input message: "Push image ${IMAGE_TAG} to registry?"
        echo 'Pushing to Registry'
      } // steps
    } // stage

  } // stages

} // pipeline
