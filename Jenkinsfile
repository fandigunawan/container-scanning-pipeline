// Example Declarative Pipeline with Anchore Scans
pipeline {
  agent { label 'master' }

  stages {
    stage('Build Image (TODO)') {
      //agent { label 'docker' }
      steps {
        echo 'Building ${IMAGE_TAG}'
        // sh "docker build -t ${IMAGE_TAG} ."
      }
    }
    stage('Push to Staging (TODO)') {
      //agent { label 'docker' }
      steps {
        echo 'Pushing ${IMAGE_TAG} to Nexus Staging'
        /*withDockerRegistry([url: 'nexus-docker.52.61.140.4.nip.io', credentialsId: 'admin/admin123']) {
          sh "docker push nexus-docker.52.61.140.4.nip.io/${IMAGE_TAG}"
        }*/
      }
    }
 
    stage('Unit testing (TODO)') {
      steps {
        echo 'Unit testing'
      } // steps
    } // stage

    stage('OpenSCAP Compliance Scan (TODO)') {
      steps {
        echo 'OpenSCAP Compliance Scan'
      } // steps
    } // stage

    stage('Twistlock Scan (TODO)') {
      steps {      
        echo 'Twistlock Scan'
      } // steps
    } // stage

    stage('Anchore Scan') {
      steps {      
        echo 'Anchore Scan'

        //Below is example command that will be needed in Push to Staging step.
        sh "echo 'nexus-docker.52.61.140.4.nip.io/${IMAGE_TAG}' > anchore_images"

        anchore bailOnFail: false, bailOnPluginFail: false, name: 'anchore_images'

        //TODO: Push reports to git repo
        
        s3Upload consoleLogLevel: 'INFO', dontWaitForConcurrentBuildCompletion: false,
            entries: [[bucket: 'dsop-pipeline-artifacts', excludedFile: '', flatten: false,
            gzipFiles: false, keepForever: false, managedArtifacts: false, noUploadOnFailure: false,
            selectedRegion: 'us-gov-east-1', showDirectlyInBrowser: false,
            path: "/var/lib/jenkins/jobs/${env.JOB_NAME}/builds/${env.BUILD_NUMBER}/archive/AnchoreReport.${env.JOB_NAME}_${env.BUILD_NUMBER}",
            //sourceFile: "/anchore_gates.json",
            includePathPattern:'**/*.json',
            storageClass: 'STANDARD', uploadFromSlave: false, useServerSideEncryption: false]], pluginFailureResultConstraint: 'FAILURE',
            userMetadata: []

      } // steps
    } // stage

    stage('Push to External Registry (TODO)') {
      steps {
        input message: "Push image ${IMAGE_TAG} to registry?"
        echo 'Pushing to Registry'
      } // steps
    } // stage

  } // stages

} // pipeline

