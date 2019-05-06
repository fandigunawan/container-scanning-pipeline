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
    NEXUS_SERVER = 'nexus-docker.52.61.140.4.nip.io'
    S3_REPORT_BUCKET = 'dsop-pipeline-artifacts'
    S3_HTML_LINK = "https://s3-us-gov-west-1.amazonaws.com/dsop-pipeline-artifacts/"
    REMOTE_HOST = 'ec2-52-222-64-188.us-gov-west-1.compute.amazonaws.com'

    S3_IMAGE_NAME = ""
    S3_IMAGE_LOCATION = ""

    S3_SIGNATURE_FILENAME = ""
    S3_SIGNATURE_LOCATION = ""

    S3_DOCUMENTATION_FILENAME = ""
    S3_DOCUMENTATION_LOCATION = ""

    S3_TAR_FILENAME = ""
    S3_TAR_LOCATION = ""

    S3_OSCAP_CVE_REPORT = "report-cve.html"
    S3_OSCAP_REPORT = "report.html"
    S3_OSCAP_LOCATION = " "

    S3_TWISTLOCK_REPORT = " "
    S3_TWISTLOCK_LOCATION = " "

    S3_ANCHORE_GATES_REPORT = "anchore_gates.json"
    S3_ANCHORE_SECURITY_REPORT = "anchore_security.json"
    S3_ANCHORE_LOCATION = " "

  }  // environment

  parameters {

    choice(choices : 'All\nOpenSCAP\nTwistlock\nAnchore',
          description: "Which tools to run?",
          name: 'toolsToRun')

    string(defaultValue: "up/ubi7-hardened-dev",
            name: 'REPO_NAME',
            description: "Name of repo to be used by Docker, Nexus and all Scanning tools")

     string(defaultValue: "latest",
            name: 'IMAGE_TAG',
            description: "Image tag to be used by Docker, Nexus and all Scanning tools")

     string(defaultValue: "RedHat",
            name: 'VENDOR_PRODUCT',
            description: "What vendor is being scanned")

    } // parameters

  stages {

    stage('Pull docker image') {

      steps {

        echo "Pushing ${REPO_NAME}:${IMAGE_TAG} to Nexus Staging"
        echo "Artifact path is   s3://${S3_REPORT_BUCKET}/${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}"

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

              withCredentials([usernamePassword(credentialsId: 'Nexus', usernameVariable: 'NEXUS_USERNAME', passwordVariable: 'NEXUS_PASSWORD')]) {
                sshCommand remote: remote, sudo: true, command: "docker login  -u ${NEXUS_USERNAME} -p '${NEXUS_PASSWORD}' ${NEXUS_SERVER};"
              } // withCredentials

              sshCommand remote: remote, command: "sudo docker pull ${image_full_path}"

            } //withCredentials
          } //node
        } // script
      }// steps
    } //stage

    stage('Run tools in parallel') {

      parallel {

        stage('OpenSCAP Scan') {

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

              S3_OSCAP_LOCATION = "${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}/openscap/"
              openscap_artifact_path = "s3://${S3_REPORT_BUCKET}/${S3_OSCAP_LOCATION}"

              node {

                withCredentials([sshUserPrivateKey(credentialsId: 'oscap', keyFileVariable: 'identity', usernameVariable: 'userName')]) {

                  image_full_path = "${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}"
                  remote.user = userName
                  remote.identityFile = identity

                  withCredentials([usernamePassword(credentialsId: 'Nexus', usernameVariable: 'NEXUS_USERNAME', passwordVariable: 'NEXUS_PASSWORD')]) {
                    sshCommand remote: remote, command: "sudo docker login  -u ${NEXUS_USERNAME} -p '${NEXUS_PASSWORD}' ${NEXUS_SERVER}"
                  }

                  //grab openSCAP version and parse
                  openScapVersionDump = sshCommand remote: remote, command: "oscap -V"
                  echo openScapVersionDump
                  def versionMatch = openScapVersionDump =~ /[0-9]+[.][0-9]+[.][0-9]+/
                  if (versionMatch) {
                    openScapVersion = '{"version": "' + versionMatch[0] + '"}'
                    echo openScapVersion
                  }

                  //must set regexp variables to null to prevent java.io.NotSerializableException
                  versionMatch = null

                  //run scans
                  sshCommand remote: remote, command: "sudo oscap-docker image ${image_full_path} xccdf eval --profile xccdf_org.ssgproject.content_profile_stig-rhel7-disa --report /tmp/${S3_OSCAP_REPORT} /usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml"
                  sshCommand remote: remote, command: "sudo oscap-docker image-cve ${image_full_path} --report /tmp/${S3_OSCAP_CVE_REPORT}"

                  //copy files to s3
                  sshCommand remote: remote, command: "/usr/sbin/aws s3 cp /tmp/${S3_OSCAP_CVE_REPORT} ${openscap_artifact_path}${S3_OSCAP_CVE_REPORT}"
                  sshCommand remote: remote, command: "/usr/sbin/aws s3 cp /tmp/${S3_OSCAP_REPORT} ${openscap_artifact_path}${S3_OSCAP_REPORT}"

                } // script
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

              S3_TWISTLOCK_REPORT = "${IMAGE_TAG}.json"
              S3_TWISTLOCK_LOCATION = "${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}/twistlock/"
              twistlock_artifact_path = "s3://${S3_REPORT_BUCKET}/${S3_TWISTLOCK_LOCATION}"

              node {

                // using the oscap user, this is temporary
                withCredentials([sshUserPrivateKey(credentialsId: 'oscap', keyFileVariable: 'identity', usernameVariable: 'userName')]) {

                  remote.user = userName
                  remote.identityFile = identity

                  // Start the container, import the TwistCLI binary, scan image
                  withCredentials([usernamePassword(credentialsId: 'TwistLock', usernameVariable: 'TWISTLOCK_USERNAME', passwordVariable: 'TWISTLOCK_PASSWORD')]) {

                      //run the TwistLock scan
                      sshCommand remote: remote, command: "sudo curl -k -ssl -u ${TWISTLOCK_USERNAME}:'${TWISTLOCK_PASSWORD}' ${TWISTLOCK_SERVER}/api/v1/util/twistcli -o twistcli && sudo chmod +x ./twistcli && sudo ./twistcli images scan ${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG} --user ${TWISTLOCK_USERNAME} --password '${TWISTLOCK_PASSWORD}' --address ${TWISTLOCK_SERVER} --details ${REPO_NAME}:${IMAGE_TAG}"

                      // TODO get version can't find an API call for this
                      // twistLockVersion = sshCommand remote: remote, command: " curl -k -u ${TWISTLOCK_USERNAME}:'${TWISTLOCK_PASSWORD}' -H 'Content-Type: application/json' -X GET ${TWISTLOCK_SERVER}/api/v1/settings/_Ping"
                      echo "${twistLockVersion}"

                      // Pull latest report from the twistlock console
                      // and save to s3
  		                sshCommand remote: remote, command: "curl -k -s -u ${TWISTLOCK_USERNAME}:'${TWISTLOCK_PASSWORD}' -H 'Content-Type: application/json' -X GET '${TWISTLOCK_SERVER}/api/v1/scans?search=${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}&limit=1&reverse=true&type=twistcli' | python -m json.tool | /usr/sbin/aws s3 cp - ${twistlock_artifact_path}${S3_TWISTLOCK_REPORT}"

                  } // withCredentials
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

            //run the anchore report using plugin
            sh "echo '${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}' > anchore_images"
            anchore bailOnFail: false, bailOnPluginFail: false, name: 'anchore_images'

            script {
              S3_ANCHORE_LOCATION = "${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}/anchore/"


              //copying anchor reports  from jenkins artifacts
              step([$class: 'CopyArtifact',
                  filter: "AnchoreReport.${JOB_NAME}_${BUILD_NUMBER}/${S3_ANCHORE_GATES_REPORT}",
                  fingerprintArtifacts: true,
                  flatten: true,
                  projectName: "${JOB_NAME}",
                  selector: [$class: 'SpecificBuildSelector',
                  buildNumber: "${BUILD_NUMBER}"],
                  target: "/tmp/${S3_ANCHORE_GATES_REPORT}"])

              step([$class: 'CopyArtifact',
                  filter: "AnchoreReport.${JOB_NAME}_${BUILD_NUMBER}/${S3_ANCHORE_SECURITY_REPORT}",
                  fingerprintArtifacts: true,
                  flatten: true,
                  projectName: "${JOB_NAME}",
                  selector: [$class: 'SpecificBuildSelector',
                  buildNumber: "${BUILD_NUMBER}"],
                  target: "/tmp/${S3_ANCHORE_SECURITY_REPORT}"])

                // copying anchore reports to S3
                withAWS(credentials:'s3BucketCredentials') {

                    s3Upload(file: "/tmp/${S3_ANCHORE_GATES_REPORT}",
                          bucket: "${S3_REPORT_BUCKET}",
                          path:"${S3_ANCHORE_LOCATION}")

                    s3Upload(file: "/tmp/${S3_ANCHORE_SECURITY_REPORT}",
                          bucket: "${S3_REPORT_BUCKET}",
                          path:"${S3_ANCHORE_LOCATION}")

                } //withAWS

              // get version
              sh(script:"curl -k https://anchore-api.52.61.140.4.nip.io/version > anchor_version.json")
              anchoreVersion = sh(script: "cat anchor_version.json", returnStdout: true)

              echo "${anchoreVersion}"

            } // script
          } // steps
        } // stage
      }// parallel
    } // stage

    stage('Write JSON documentaion') {
      steps {

        script {

          def anchorJSON = new JsonSlurper().parseText(anchoreVersion)
          def twistLockJSON = new JsonSlurper().parseText(twistLockVersion)
          def openScapJSON = new JsonSlurper().parseText(openScapVersion)

          S3_DOCUMENTATION_FILENAME = "documentation.json"
          S3_DOCUMENTATION_LOCATION = "${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}/${S3_DOCUMENTATION_FILENAME}"

          def json_documentation = JsonOutput.toJson(timestamp: "${DATETIME_TAG}",
                git: [hash: "${GIT_COMMIT}",
                      branch: "${GIT_BRANCH}"],
                jenkins: [buildTag: "${BUILD_TAG}",
                          buildID: "${BUILD_ID}",
                          buildNumber: "${BUILD_NUMBER}"],
                tools: [anchore: anchorJSON,
                        openSCAP: openScapJSON,
                        twistLock: twistLockJSON ])

          //must clear out all JsonSlurper variables
          // to prevent a serialization error
          anchorJSON = null
          twistLockJSON = null
          openScapJSON = null


          //save it to text file to prevent serialization problem
          writeFile(file: 'documentation.json', text: json_documentation.toString())
          jsonText = readFile(file: 'documentation.json')
          echo "${jsonText}"


          //save documentation to S3
          withAWS(credentials:'s3BucketCredentials') {
              s3Upload(file: "documentation.json",
                    bucket: "${S3_REPORT_BUCKET}",
                    path:"${S3_DOCUMENTATION_LOCATION}")
          } // withAWS


        } // script
      } // steps
    } // stage

    stage('Signing image') {
      environment {
        //this is file reference
        SIGNING_KEY = credentials('ContainerSigningKey')
        //actual passphrase
        SIGNING_KEY_PASSPHRASE = credentials('ContainerSigningKeyPassphrase')
      }  // environment

      steps {

        script {
          def remote = [:]
          remote.name = "node"
          remote.host = "${env.REMOTE_HOST}"
          remote.allowAnyHosts = true
          repoNoSlash = REPO_NAME.replaceAll("/", "-")

          S3_SIGNATURE_FILENAME = "signature.sha"
          S3_SIGNATURE_LOCATION = "${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}/${S3_SIGNATURE_FILENAME}"

          S3_IMAGE_NAME = "${repoNoSlash}-${IMAGE_TAG}"
          S3_IMAGE_LOCATION = "${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}/${S3_IMAGE_NAME}"
          //siging the image
          node {

            echo 'Signing container'

            //store path and name of image on s3
            withCredentials([sshUserPrivateKey(credentialsId: 'oscap', keyFileVariable: 'identity', usernameVariable: 'userName')]) {
              remote.user = userName
              remote.identityFile = identity


              def unixTime = sh(
                         script: 'date +%s',
                         returnStdout: true
                       ).trim().toString()

              echo unixTime
              
              def containerDocumentation = """{
                  \"critical\": {
                      \"type\": \"atomic container signature\",
                      \"image\": {
                          \"docker-manifest-digest\": \"sha256:817a12c32a39bbe394944ba49de563e085f1d3c5266eb8e9723256bc4448680e\"
                      },
                      \"identity\": {
                          \"docker-reference\": \"docker.io/library/busybox:latest\"
                      }
                  },
                  \"optional\": {
                      \"creator\": \"pgp vVERSION\",
                      \"timestamp\": ${unixTime},
                  }
              }"""

              echo containerDocumentation

              writeFile(file: 'container_documentation.json', text: containerDocumentation)
              signature = sh "g=\$(mktemp -d) && f=\$(mktemp) && trap \"rm \$f;rm -rf \$g\" EXIT || exit 255;gpg --homedir \$g --import --batch --passphrase ${SIGNING_KEY_PASSPHRASE} ${SIGNING_KEY} ;gpg --detach-sign --homedir \$g -o \$f --armor --yes --batch --passphrase ${SIGNING_KEY_PASSPHRASE} container_documentation.json;cat \$f;"

              echo signature

              //sshPut remote: remote, from: "${SIGNING_KEY}", into: './signingkey'
              //signature = sshCommand remote: remote, command: "g=\$(mktemp -d) && f=\$(mktemp) && e=\$(mktemp) && trap \"sudo rm \$e;sudo rm \$f;sudo rm -rf \$g\" EXIT || exit 255;sudo docker save -o \$e ${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG};sudo chmod o=r \$e;gpg --homedir \$g --import --batch --passphrase ${SIGNING_KEY_PASSPHRASE} ./signingkey ;echo \$e;gpg --detach-sign --homedir \$g -o \$f --armor --yes --batch --passphrase ${SIGNING_KEY_PASSPHRASE} \$e;/usr/sbin/aws s3 cp \$e  s3://${S3_REPORT_BUCKET}/${S3_IMAGE_LOCATION};rm ./signingkey;cat \$f;"

              def signatureMatch = signature =~ /(?s)-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----/
              def signature = ""
              if (signatureMatch) {

                 signature = signatureMatch[0]
              }
              //must set regexp variables to null to prevent java.io.NotSerializableException
              signatureMatch = null


              withAWS(credentials:'s3BucketCredentials') {

                  def currentIdent = awsIdentity()
                  writeFile(file: 'signature.sha', text: signature)

                  s3Upload(file: "signature.sha",
                        bucket: "${S3_REPORT_BUCKET}",
                        path:"${S3_SIGNATURE_LOCATION}")


              } //withAWS
            } // withCredentials
          } // node
        }//script
      } // steps
    } // stage

    stage('Create tar of all output') {
      steps {
        script {

          S3_TAR_FILENAME = "${repoNoSlash}-${IMAGE_TAG}-full.tar.gz"
          S3_TAR_LOCATION = "${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}/"
          withAWS(credentials:'s3BucketCredentials') {

            repoNoSlash = REPO_NAME.replaceAll("/", "-")

            s3Download(file:'output',
                    bucket:"${S3_REPORT_BUCKET}",
                    path: "${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}/",
                    force:true)

              sh "tar cvfz ${S3_TAR_FILENAME} output/${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}/"

              s3Upload(file: "${S3_TAR_FILENAME}",
                    bucket: "${S3_REPORT_BUCKET}",
                    path:"${VENDOR_PRODUCT}/${REPO_NAME}/${IMAGE_TAG}/${DATETIME_TAG}_${BUILD_NUMBER}/")

              sh "rm -fr output;rm ${S3_TAR_FILENAME}"

          } //withAWS
        } //script
      } // steps
    } // stage Create tar of all output

    stage('Update directory') {
      steps {
        script {
          withAWS(credentials:'s3BucketCredentials') {


            headerSlug = "<!DOCTYPE html><html><body><h1>Directory of ${VENDOR_PRODUCT} - ${REPO_NAME} Testing Artifacts</h1><p>\n-------------------------------------------------------<p>\n<p>\n<p>\n<p>\n<p>"
            footerSlug = "-------------------------------------------------------</body></html>"
            repoNoSlash = REPO_NAME.replaceAll("/", "-")

            //first time this runs there is no file so need to create
            try {
              s3Download(file:'repo_map.html',
                      bucket:"${S3_REPORT_BUCKET}",
                      path: "${VENDOR_PRODUCT}/${REPO_NAME}/repo_map.html",
                      force:true)
            } catch(AmazonS3Exception) {
              sh "echo '${headerSlug}' > repo_map.html"
            }


            //read file and look for header
            map = readFile(file: 'repo_map.html')

            def headerMatch = map =~ /(?s)(-------------------------------------------------------)(.*)/
            def previousRuns = ""
            if (headerMatch) {
               previousRuns = headerMatch[0][2]
            }
            //must set regexp variables to null to prevent java.io.NotSerializableException
            headerMatch = null

            echo previousRuns

            // add this run
            newFile = headerSlug +
                "<h2>Run for ${BUILD_NUMBER} using with tag:${IMAGE_TAG}</h2>\n" +
                "Image scanned - <a href=\"${S3_HTML_LINK}${S3_IMAGE_LOCATION}\"> ${S3_IMAGE_NAME}  </a><br>\n" +
                "PGP Signature - <a href=\"${S3_HTML_LINK}${S3_SIGNATURE_LOCATION}\"> ${S3_SIGNATURE_FILENAME}  </a><br>\n" +
                "Version Documentation - <a href=\"${S3_HTML_LINK}${S3_DOCUMENTATION_LOCATION}\"> ${S3_DOCUMENTATION_FILENAME}  </a><br>\n" +
                "<h4>Tool reports:</h3>\n" +
                "OpenSCAP - <a href=\"${S3_HTML_LINK}${S3_OSCAP_LOCATION}${S3_OSCAP_REPORT}\"> ${S3_OSCAP_REPORT}  </a>, <a href=\"${S3_HTML_LINK}${S3_OSCAP_LOCATION}${S3_OSCAP_CVE_REPORT}\"> ${S3_OSCAP_CVE_REPORT}  </a><br>\n" +
                "TwistLock - <a href=\"${S3_HTML_LINK}${S3_TWISTLOCK_LOCATION}${S3_TWISTLOCK_REPORT}\"> ${S3_TWISTLOCK_REPORT}  </a><br>\n" +
                "Anchore - <a href=\"${S3_HTML_LINK}${S3_ANCHORE_LOCATION}${S3_ANCHORE_GATES_REPORT}\"> ${S3_ANCHORE_GATES_REPORT}  </a>, <a href=\"${S3_HTML_LINK}${S3_ANCHORE_LOCATION}${S3_ANCHORE_SECURITY_REPORT}\"> ${S3_ANCHORE_SECURITY_REPORT}  </a><br>\n" +
                "<p><p>" +
                previousRuns +
                footerSlug

            echo newFile

            writeFile(file: 'repo_map.html', text: newFile)



            s3Upload(file: "repo_map.html",
                  bucket: "${S3_REPORT_BUCKET}",
                  path:"${VENDOR_PRODUCT}/${REPO_NAME}/")


          } //withAWS
        } //script
      } // steps
    } // stage Update directory


    stage('Push to External Registry (TODO)') {

      steps {
        echo "Push to external registry"
      }


    } // stage Push to External Registry

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

              sshCommand remote: remote, command: "if [[ \$(sudo docker images -q) ]]; then sudo docker rmi \$(sudo docker images -q) --force; fi && if [[ \$(sudo docker ps -a -q) ]]; then sudo docker rm \$(sudo docker ps -a -q); fi"

	          } //withCredentials
	        } // node
        } // script
      } // steps
    } // stage Clean up Docker artifacts

  } // stages
} // pipeline
