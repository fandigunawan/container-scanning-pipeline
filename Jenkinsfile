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
    NEXUS_USERNAME = credentials('NexusUsername')
    NEXUS_PASSWORD = credentials('NexusPassword')
    S3_REPORT_BUCKET = 'dsop-pipeline-artifacts'
    S3_HTML_LINK = "https://s3-us-gov-west-1.amazonaws.com/dsop-pipeline-artifacts/"
    OSCAP_NODE = credentials('OpenSCAPNode')
    GPG_KEY = "test_dod@redhat.com"
    PUBLIC_DOCKER_HOST = "${NEXUS_SERVER}"
    PUBLIC_IMAGE_SHA = ""
    PUBLIC_IMAGE_TAG = ""

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
    S3_IMAGE_SIGNATURE = ""
    S3_IMAGE_SIGNATURE_LOCATION = ""

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

    stage('Initializing Environment') {
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
          S3_IMAGE_SIGNATURE = "${repo_image_only}-${IMAGE_TAG}.sig"
          S3_IMAGE_SIGNATURE_LOCATION = "${BASIC_PATH_FOR_DATA}/${S3_IMAGE_SIGNATURE}"

          S3_IMAGE_LOCATION = "${BASIC_PATH_FOR_DATA}/${S3_IMAGE_NAME}"
          S3_TAR_FILENAME = "${repo_image_only}-${IMAGE_TAG}-reports-signature.tar.gz"

          S3_TAR_LOCATION = "${BASIC_PATH_FOR_DATA}/${S3_TAR_FILENAME}"

          S3_CSV_LOCATION = "${BASIC_PATH_FOR_DATA}/csvs/"

        } //script
      } // steps
    } // stage Initializing environment


    stage('Pull Docker Image') {
      steps {

        echo "Pushing ${REPO_NAME}:${IMAGE_TAG} to Nexus Staging"
        echo "Artifact path is   s3://${S3_REPORT_BUCKET}/${BASIC_PATH_FOR_DATA}/"

        script {

          def remote = [:]
          remote.name = "node"
          remote.host = "${env.OSCAP_NODE}"
          remote.allowAnyHosts = true
          openscap_artifact_path = "s3://${S3_REPORT_BUCKET}/${BASIC_PATH_FOR_DATA}/openscap/"

          node {

            withCredentials([sshUserPrivateKey(credentialsId: 'secure-build', keyFileVariable: 'identity', usernameVariable: 'userName')]) {

              image_full_path = "${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}"
              
              remote.user = userName
              remote.identityFile = identity

              sshCommand remote: remote, sudo: true, command: "podman login  -u ${NEXUS_USERNAME} -p '${NEXUS_PASSWORD}' ${NEXUS_SERVER};"

              sshCommand remote: remote, command: "sudo podman pull ${image_full_path}"
              dcarApproval = sshCommand remote: remote, command: "sudo podman inspect -f '{{.Config.Labels.dcar_status}}' ${image_full_path}"
              PUBLIC_IMAGE_SHA = sshCommand remote: remote, command: "sudo podman inspect -f '{{.Digest}}' ${image_full_path}"

            } //withCredentials
          } //node
        } // script
      }// steps
    } //stage

    stage('Run Scans in Parallel') {

      parallel {

        stage('OpenSCAP Compliance Scan') {

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
              remote.host = "${env.OSCAP_NODE}"
              remote.allowAnyHosts = true

              openscap_artifact_path = "s3://${S3_REPORT_BUCKET}/${S3_OSCAP_LOCATION}"

              node {

                withCredentials([sshUserPrivateKey(credentialsId: 'secure-build', keyFileVariable: 'identity', usernameVariable: 'userName')]) {

                  image_full_path = "${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}"
                  remote.user = userName
                  remote.identityFile = identity

                  sshCommand remote: remote, command: "sudo docker login  -u ${NEXUS_USERNAME} -p '${NEXUS_PASSWORD}' ${NEXUS_SERVER}"

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

                  //copy files to s3
                  sshCommand remote: remote, command: "/usr/bin/aws s3 cp /tmp/${S3_OSCAP_REPORT} ${openscap_artifact_path}${S3_OSCAP_REPORT}"

              } // withCredentials
            } //node
          } //script
         } // steps
        } // stage

        stage('OpenSCAP CVE Scan') {

          when {
            anyOf {
              environment name: "toolsToRun", value: "All"
              environment name: "toolsToRun", value: "OpenSCAP"
            } // anyOf
          } // when

          steps {
            echo 'OpenSCAP CVE Scan'

            script {

              def remote = [:]
              remote.name = "node"
              remote.host = "${env.OSCAP_NODE}"
              remote.allowAnyHosts = true

              openscap_artifact_path = "s3://${S3_REPORT_BUCKET}/${S3_OSCAP_LOCATION}"

              node {

                withCredentials([sshUserPrivateKey(credentialsId: 'secure-build', keyFileVariable: 'identity', usernameVariable: 'userName')]) {

                  image_full_path = "${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}"
                  remote.user = userName
                  remote.identityFile = identity

                  sshCommand remote: remote, command: "sudo docker login  -u ${NEXUS_USERNAME} -p '${NEXUS_PASSWORD}' ${NEXUS_SERVER}"

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
                  sshCommand remote: remote, command: "sudo oscap-docker image-cve ${image_full_path} --report /tmp/${S3_OSCAP_CVE_REPORT}"

                  //copy files to s3
                  sshCommand remote: remote, command: "/usr/bin/aws s3 cp /tmp/${S3_OSCAP_CVE_REPORT} ${openscap_artifact_path}${S3_OSCAP_CVE_REPORT}"

              } // withCredentials
             } //node
            } //script
          } // steps
        } // stage

        stage('Twistlock Scan') {

          environment {
            TWISTLOCK_NODE = credentials('TwistLockServerAddress')
            TWISTLOCK_SERVER = "https://${TWISTLOCK_NODE}"
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
              remote.host = "${env.OSCAP_NODE}"
              remote.allowAnyHosts = true

              twistlock_artifact_path = "s3://${S3_REPORT_BUCKET}/${S3_TWISTLOCK_LOCATION}"

              node {

                // using the oscap user, this is temporary
                withCredentials([sshUserPrivateKey(credentialsId: 'secure-build', keyFileVariable: 'identity', usernameVariable: 'userName')]) {

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
  		                sshCommand remote: remote, command: "curl -k -s -u ${TWISTLOCK_USERNAME}:'${TWISTLOCK_PASSWORD}' -H 'Content-Type: application/json' -X GET '${TWISTLOCK_SERVER}/api/v1/scans?search=${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}&limit=1&reverse=true&type=twistcli' | python -m json.tool | /usr/bin/aws s3 cp - ${twistlock_artifact_path}${S3_TWISTLOCK_REPORT}"

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

          environment {
            ANCHORE_NODE = credentials('AnchoreServerAddress')
          }  // environment

          steps {
            echo 'Anchore Scan'

            //run the anchore report using plugin
            sh "echo '${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}' > anchore_images"
            anchore bailOnFail: false, bailOnPluginFail: false, name: 'anchore_images'

            script {


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
              sh(script:"curl -k https://${ANCHORE_NODE}/version > anchor_version.json")
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

    stage('Sign and Copy Image to S3') {
      agent { label 'oscap' }
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
          remote.host = "${env.OSCAP_NODE}"
          remote.allowAnyHosts = true

          echo "test stage"

          
          //store path and name of image on s3
          withCredentials([file(credentialsId: 'ContainerSigningKey', variable: 'PRIVATE_KEY')]) {
          
            output = sh(script: """e=\$(mktemp) && f=\$(mktemp) && trap \" rm \$f;  rm \$e \" EXIT || exit 255;
            sudo podman save --format=oci-archive -o \$e ${NEXUS_SERVER}/${REPO_NAME}@${PUBLIC_IMAGE_SHA};
            gpg --detach-sign --default-key FF28F74A --passphrase '${SIGNING_KEY_PASSPHRASE}'  --batch --yes --armor -o \$f  \$e ; cat \$f;
            sha256sum \$e;
            sudo chmod o+r \$e;/usr/bin/aws s3 cp \$e  s3://${S3_REPORT_BUCKET}/${S3_IMAGE_LOCATION};""" , returnStdout: true)
            
            tar_sha256 = ""
            def matcher = output =~ /\b[A-Fa-f0-9]{64}\b/
            if(!matcher){
              error("could not extract sha256 from image tar")
            }
            tar_sha256 = matcher[0]
            echo "SHA256 TAR $tar_sha256"

            def signatureMatch = output =~ /(?s)-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----/
            sig = ""
            
            if (signatureMatch) {
              echo "found signature"
              sig = signatureMatch[0]
              //must set regexp variables to null to prevent java.io.NotSerializableException
              signatureMatch = null
            } 
            else {
              error("could not extract gpg signature from image tar")
            }
          } // withCredentials
          echo "enter aws block"
          withAWS(credentials:'s3BucketCredentials') {
                
                def currentIdent = awsIdentity()

                writeFile(file:"${S3_IMAGE_SIGNATURE}", text: sig)

                echo "uploading"
                s3Upload(file: "${S3_IMAGE_SIGNATURE}",
                      bucket: "${S3_REPORT_BUCKET}",
                      path:"${S3_IMAGE_SIGNATURE_LOCATION}")
                echo "uploaded"
          } //withAWS
        }//script
      } // steps
    } // stage

    stage('Signing Manifest') {
      environment {
        //this is file reference
        SIGNING_KEY = credentials('ContainerSigningKey')
        //actual passphrase
        SIGNING_KEY_PASSPHRASE = credentials('ContainerSigningKeyPassphrase')
      }  // environment

      steps {

        script {

          //siging the image
          node {

            echo 'Signing Manifest'

              def unixTime = sh(
                         script: 'date +%s',
                         returnStdout: true
                       ).trim().toString()

              def gpgVersionOutput = sh(script: "gpg --version", returnStdout: true).trim()
              def gpgMatch = gpgVersionOutput =~ /gpg.*[0-9]+[.][0-9]+[.][0-9]+/
              def gpgVersion = ""
              if (gpgMatch) {
                 gpgVersion = gpgMatch[0]
              }
              //must set regexp variables to null to prevent java.io.NotSerializableException
              gpgMatch = null
              echo gpgVersion

              def containerDocumentation = """
              {
                \"critical\": {
                    \"type\": \"atomic container signature\",
                    \"image\": {
                        \"podman-manifest-digest\": \"${PUBLIC_IMAGE_SHA}\",
                        \"image-tar-sha256-checksum\" : \"$tar_sha256\"
                    },
                    \"identity\": {
                        \"podman-reference\": \"${PUBLIC_DOCKER_HOST}/${REPO_NAME}:${IMAGE_TAG}\"
                    }
                },
                \"optional\": {
                    \"creator\": \"${gpgVersion}\",
                    \"timestamp\": ${unixTime}
                }
            }
            """
              echo containerDocumentation

              writeFile(file: "${S3_MANIFEST_NAME}", text: containerDocumentation)

              withCredentials([file(credentialsId: 'ContainerSigningKey', variable: 'PRIVATE_KEY')]) {
                signature = sh(script: "g=\$(mktemp -d) && f=\$(mktemp) && trap \"rm \$f;rm -rf \$g\" EXIT || exit 255;gpg --homedir \$g --import --batch --passphrase '${SIGNING_KEY_PASSPHRASE}' ${PRIVATE_KEY} ;gpg --detach-sign --homedir \$g -o \$f --armor --yes --batch --passphrase '${SIGNING_KEY_PASSPHRASE}' ${S3_MANIFEST_NAME};cat \$f;",
                            returnStdout: true)
              } //withCredentials


              def signatureMatch = signature =~ /(?s)-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----/
              def signature = ""
              if (signatureMatch) {
                 signature = signatureMatch[0]
              }
              //must set regexp variables to null to prevent java.io.NotSerializableException
              signatureMatch = null


              withAWS(credentials:'s3BucketCredentials') {

                  def currentIdent = awsIdentity()
                  writeFile(file: "${S3_SIGNATURE_FILENAME}", text: signature)

                  s3Upload(file: "${S3_MANIFEST_NAME}",
                        bucket: "${S3_REPORT_BUCKET}",
                        path:"${S3_MANIFEST_LOCATION}")

                  s3Upload(file: "${S3_SIGNATURE_FILENAME}",
                        bucket: "${S3_REPORT_BUCKET}",
                        path:"${S3_SIGNATURE_LOCATION}")


              } //withAWS
          } // node
        }//script
      } // steps
    } // stage

    stage('Download Tools and Scans') {
      steps {
        script {
          withAWS(credentials:'s3BucketCredentials') {
            s3Download(file:'output',
                bucket:"${S3_REPORT_BUCKET}",
                path: "${BASIC_PATH_FOR_DATA}/",
                force:true)

            echo "output/${BASIC_PATH_FOR_DATA}/"
          } //withAWS
          
          sh "wget -c https://dccscr.dsop.io/dsop/container-scanning-pipeline/raw/master/pipeline_python/pipeline_csv_gen.py -P output/"
          sh "wget -c https://dccscr.dsop.io/dsop/container-scanning-pipeline/raw/master/pipeline_python/pipeline_wl_compare.py -P output/"
          echo "downloaded python scripts."
          
        } //script
      } // steps
    } // stage AWS Download

    stage('Create CSV Scan Output') {
      steps {
        script {

          echo "sh /opt/rh/rh-python36/root/bin/python3 output/pipeline_csv_gen.py output/${S3_OSCAP_LOCATION}${S3_OSCAP_REPORT} output/${S3_OSCAP_LOCATION}${S3_OSCAP_CVE_REPORT} output/${S3_TWISTLOCK_LOCATION}${S3_TWISTLOCK_REPORT} output/${S3_ANCHORE_LOCATION}${S3_ANCHORE_SECURITY_REPORT} output/${S3_ANCHORE_LOCATION}${S3_ANCHORE_GATES_REPORT} output/${S3_CSV_LOCATION}"
          sh "/opt/rh/rh-python36/root/bin/python3 output/pipeline_csv_gen.py output/${S3_OSCAP_LOCATION}${S3_OSCAP_REPORT} output/${S3_OSCAP_LOCATION}${S3_OSCAP_CVE_REPORT} output/${S3_TWISTLOCK_LOCATION}${S3_TWISTLOCK_REPORT} output/${S3_ANCHORE_LOCATION}${S3_ANCHORE_SECURITY_REPORT} output/${S3_ANCHORE_LOCATION}${S3_ANCHORE_GATES_REPORT} output/${S3_CSV_LOCATION}"

        // upload to S3
        withAWS(credentials:'s3BucketCredentials') {

            def currentIdent = awsIdentity()
            writeFile(file: "${S3_SIGNATURE_FILENAME}", text: signature)

            s3Upload(file: "output/${S3_CSV_LOCATION}",
                  bucket: "${S3_REPORT_BUCKET}",
                  path:"${S3_CSV_LOCATION}")

          } //withAWS
          
        } //script
      } // steps
    } // stage Create CSV Output

    stage('Check CVEs Against Whitelist') {
      steps {
        script {
          //error out if this is a production run and there are findings
          //if no findings or a test, proceed
          try {
            echo "${REPO_NAME} ${IMAGE_TAG}"
            echo "sh /opt/rh/rh-python36/root/bin/python3 output/pipeline_wl_compare.py ${REPO_NAME} ${IMAGE_TAG} output/${S3_OSCAP_LOCATION}${S3_OSCAP_REPORT} output/${S3_OSCAP_LOCATION}${S3_OSCAP_CVE_REPORT} output/${S3_TWISTLOCK_LOCATION}${S3_TWISTLOCK_REPORT} output/${S3_ANCHORE_LOCATION}${S3_ANCHORE_SECURITY_REPORT} output/${S3_ANCHORE_LOCATION}${S3_ANCHORE_GATES_REPORT}"
            sh "/opt/rh/rh-python36/root/bin/python3 output/pipeline_wl_compare.py ${REPO_NAME} ${IMAGE_TAG} output/${S3_OSCAP_LOCATION}${S3_OSCAP_REPORT} output/${S3_OSCAP_LOCATION}${S3_OSCAP_CVE_REPORT} output/${S3_TWISTLOCK_LOCATION}${S3_TWISTLOCK_REPORT} output/${S3_ANCHORE_LOCATION}${S3_ANCHORE_SECURITY_REPORT} output/${S3_ANCHORE_LOCATION}${S3_ANCHORE_GATES_REPORT}"
          } catch(exception) {
            //whilelist scan failed for whatever reason
            if (testOrProduction == "Test") {
              echo "Whitelist comparison failed, proceeding since this is a test run."
            } else if (dcarApproval != "approved") {
              echo "Whitelist comparison failed, proceeding since container is not yet approved."
            } else {
              error("Build failed due to non-Whitelisted CVEs being found and container is in \"approved\" status.")
            }
          } //end try block

        } //script
      } // steps
    } // stage Check Whitelist

    stage('Tar and Upload Artifacts to AWS') {
      steps {
        script {
          withAWS(credentials:'s3BucketCredentials') {

            echo "output/${BASIC_PATH_FOR_DATA}/"
            sh "tar cvfz ${S3_TAR_FILENAME} -C output/${ROOT_FOR_REPO_IMAGE}/  ${SPECIFIC_FOLDER_FOR_RUN}"

            s3Upload(file: "${S3_TAR_FILENAME}",
                bucket: "${S3_REPORT_BUCKET}",
                path:"${BASIC_PATH_FOR_DATA}/")

            sh "rm -fr output;rm ${S3_TAR_FILENAME}"

          } //withAWS
        } //script
      } // steps
    } // stage Create tar of all output, delete Artifacts


    
    stage('Create Repository Mapping Website') {

      environment {
        PUBLIC_KEY = credentials('ContainerSigningPublicKey')
      }  // environment

      steps {
        script {
          withAWS(credentials:'s3BucketCredentials') {

            def publicKey = sh(script: "cat ${PUBLIC_KEY}", returnStdout: true)
            
            headerSlug = "<!DOCTYPE html><html><body>" +
              "<h1>${REPO_NAME} Artifacts</h1>" +
              "<h3>Container Approval Status: ${dcarApproval}</h3>" +
              "<p> Image manifests have been signed with key:<br>" +
              "<pre>${publicKey}</pre>" +
              "<p>Verifying Image Instructions:<ol>" +
              "<li>Save key to file (call it public.asc)</li>" +
              "<li>Import key with:<code> gpg --import public.asc </code></li>" +
              "<li>Create a personal gpg key if not yet created</li>" +
              "<li>Trust the imported public key:<code>  gpg --sign-key test_dod@redhat.com  </code></li>" +
              "<li>Download the image manifest (manifest.json) and PGP signature (signature.sig) below</li>" +
              "<li>Verify with:<code> gpg --verify signature.sig manifest.json</code></li>" +
              "<li>Verify that the sha tag matches the signed manifest.json entry for the manifest-digest: ${PUBLIC_IMAGE_SHA}" +
              "<li>Hash the image to verify that the result matches the sha256 checksum entry in manifest.json: <code> sha256sum ${S3_TAR_FILENAME}</code>" +
              "</ol>" +
              "<p>Downloading and Running the image:<ol>" +
              "<li>Find the SHA tag for run below: ex: ${PUBLIC_IMAGE_SHA}" +
              "<li>Retrieve the image by downloading it: <a href=\"${S3_HTML_LINK}${S3_IMAGE_LOCATION}\"> ${S3_IMAGE_NAME}  </a></li>" + 
              "<li>Load the image into local podman registry: <code> podman load -i ./${S3_IMAGE_NAME} </code></li>" +
              "<li>Run the image with:<code> podman run ${REPO_NAME}:${IMAGE_TAG} </code></li>" +
              "</ol>" +
              "<p>\n-------------------------------------------------------<p>\n<p>\n<p>\n<p>\n<p>"

            footerSlug = "-------------------------------------------------------</body></html>"
            
            //first time this runs there is no file so need to create
            try {
              s3Download(file:'repo_map.html',
                      bucket:"${S3_REPORT_BUCKET}",
                      path: "${ROOT}/repo_map.html",
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

            //echo previousRuns

            // add this run
            newFile = headerSlug +
                "<h2>Run for ${BUILD_NUMBER} using with tag:${IMAGE_TAG}</h2>\n" +
                "SHA tag - ${PUBLIC_IMAGE_SHA}<br>\n" +
                "Image scanned - <a href=\"${S3_HTML_LINK}${S3_IMAGE_LOCATION}\"> ${S3_IMAGE_NAME}  </a><br>\n" +
                "Image manifest  - <a href=\"${S3_HTML_LINK}${S3_MANIFEST_LOCATION}\"> ${S3_MANIFEST_NAME}  </a><br>\n" +
                "PGP Signature - <a href=\"${S3_HTML_LINK}${S3_SIGNATURE_LOCATION}\"> ${S3_SIGNATURE_FILENAME}  </a><br>\n" +
                "Version Documentation - <a href=\"${S3_HTML_LINK}${S3_DOCUMENTATION_LOCATION}\"> ${S3_DOCUMENTATION_FILENAME}  </a><br>\n" +
                "Tar of reports and signature - <a href=\"${S3_HTML_LINK}${S3_TAR_LOCATION}\"> ${S3_TAR_FILENAME}  </a><br>\n" +
                "<h4>Tool reports:</h3>\n" +
                "OpenSCAP - <a href=\"${S3_HTML_LINK}${S3_CSV_LOCATION}oscap.csv\"> Compliance  </a>, <a href=\"${S3_HTML_LINK}${S3_CSV_LOCATION}oval.csv\"> OVAL  </a><br>\n" +
                "TwistLock - <a href=\"${S3_HTML_LINK}${S3_CSV_LOCATION}tl.csv\"> TwistLock  </a><br>\n" +
                "Anchore - <a href=\"${S3_HTML_LINK}${S3_CSV_LOCATION}anchore_gates.csv\"> Gates </a>, <a href=\"${S3_HTML_LINK}${S3_CSV_LOCATION}anchore_security.csv\"> Security  </a><br>\n" +
                "Summary Report - <a href=\"${S3_HTML_LINK}${S3_CSV_LOCATION}summary.csv\"> Summary  </a><br>\n" +
                "<p><p>" +
                "Full Report - <a href=\"${S3_HTML_LINK}${S3_CSV_LOCATION}all_scans.xlsx\"> All Scans rolled up into one Excel File</a><br>\n" +
                previousRuns +
                footerSlug

            def this_run_repo = [:]
            this_run_repo.put("Repo_Name","${REPO_NAME}")
            this_run_repo.put("Approval_Status","${dcarApproval}")
            this_run_repo.put("Public_Key","${publicKey}")
            this_run_repo.put("Image_Sha","${PUBLIC_IMAGE_SHA}")
            this_run_repo.put("Image_Name","${S3_IMAGE_NAME}")
            this_run_repo.put("Image_Tag","${IMAGE_TAG}")
            this_run_repo.put("HTML_Link","${S3_HTML_LINK}${S3_IMAGE_LOCATION}")
            //old header slug would end here but all in same json key
            this_run_repo.put("Build_Number","${BUILD_NUMBER}")
            this_run_repo.put("Image_Manifest ","${S3_HTML_LINK}${S3_MANIFEST_LOCATION}")
            this_run_repo.put("Manifest_Name","${S3_MANIFEST_NAME}")
            this_run_repo.put("PGP_Signature","${S3_HTML_LINK}${S3_SIGNATURE_LOCATION}")
            this_run_repo.put("Signature_Name","${S3_SIGNATURE_FILENAME}")
            this_run_repo.put("Version_Documentation","${S3_HTML_LINK}${S3_DOCUMENTATION_LOCATION}")
            this_run_repo.put("Tar_Location","${S3_HTML_LINK}${S3_TAR_LOCATION}")
            this_run_repo.put("Tar_Name","${S3_TAR_FILENAME}")
            this_run_repo.put("OpenSCAP_Compliance_Results","${S3_HTML_LINK}${S3_CSV_LOCATION}oscap.csv")
            this_run_repo.put("OpenSCAP_OVAL_Results","${S3_HTML_LINK}${S3_CSV_LOCATION}oval.csv")
            this_run_repo.put("TwistLock_Results","${S3_HTML_LINK}${S3_CSV_LOCATION}tl.csv")
            this_run_repo.put("Anchore_Gates_Results","${S3_HTML_LINK}${S3_CSV_LOCATION}anchore_gates.csv")
            this_run_repo.put("Anchore_Security_Results","${S3_HTML_LINK}${S3_CSV_LOCATION}anchore_security.csv")
            this_run_repo.put("Summary_Report","${S3_HTML_LINK}${S3_CSV_LOCATION}summary.csv")
            this_run_repo.put("Full_Report","${S3_HTML_LINK}${S3_CSV_LOCATION}all_scans.xlsx")
            
            //first time this runs there is no file so need to create
            b_prev_json = true
            try {
              s3Download(file:'repo_map.json',
                      bucket:"${S3_REPORT_BUCKET}",
                      path: "${ROOT}/repo_map.json",
                      force:true)
            } catch(AmazonS3Exception) {
              b_prev_json =false
            }
        
            repo_map=[:]
            repo_map_json = ""
            if(b_prev_json){
              prev_json_file = readFile(file: 'repo_map.json')
              prev_json = prev_json_file.substring(1);
              echo prev_json
      
              repo_map.put( "${BUILD_NUMBER}", this_run_repo )
            
              repo_map_json = JsonOutput.toJson( repo_map )
              
              repo_map_json = repo_map_json.replaceAll("}}","} ,")
              echo repo_map_json
              repo_map_json = repo_map_json + prev_json
                
            }
            else{
              echo "else statement"
              repo_map.put( "${BUILD_NUMBER}", this_run_repo )
              repo_map_json = JsonOutput.toJson( repo_map )
            }
            
            echo "repo_map.. \n"
            echo repo_map_json
            writeFile(file: 'repo_map.html', text: newFile)
            
            writeFile(file: 'repo_map.json', text: repo_map_json)
            //clean up for serializeable errors in new json libs 
            this_run_repo = null
            prev_json = null 
            repo_map = null
            repo_map_json = null

            s3Upload(file: "repo_map.html",
                  bucket: "${S3_REPORT_BUCKET}",
                  path:"${ROOT}/")

            s3Upload(file: "repo_map.json",
                  bucket: "${S3_REPORT_BUCKET}",
                  path:"${ROOT}/")

            //record this as the latest in DynamoDB

          } //withAWS
        } //script
      } // steps
    } // stage Update directory

//    stage('Clean up Docker artifacts') {
//      steps {

//        echo 'Cleaning up docker artifacts'

        // this may use a dedicated node eventually, or be refactored to follow best practice TBD
//        script {

//          def remote = [:]
//          remote.name = "node"
//          remote.host = "${env.OSCAP_NODE}"
//          remote.allowAnyHosts = true

//          node {

            // using the oscap user, this is temporary
//            withCredentials([sshUserPrivateKey(credentialsId: 'secure-build', keyFileVariable: 'identity', usernameVariable: 'userName')]) {

//              remote.user = userName
//              remote.identityFile = identity

//              sshCommand remote: remote, command: "if [[ \$(sudo podman images -q ${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}) ]]; then sudo podman rmi ${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG} --force; fi && if [[ \$(sudo podman ps -a -q | grep ${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}) ]]; then sudo podman rm ${NEXUS_SERVER}/${REPO_NAME}:${IMAGE_TAG}; fi"

//	          } //withCredentials
//	        } // node
//        } // script
//      } // steps
//    } // stage Clean up Docker artifacts

  } // stages
} // pipeline
