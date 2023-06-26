pipeline {
    agent any

    tools {
          maven 'Maven 3.6.3'
    }

    environment {
      APP_NAME = "honeypot"
      
      ARTIFACTORY_SERVER = "https://registry.iotac.rid-intrasoft.eu/artifactory/iotacregistry/"
      ARTIFACTORY_DOCKER_REGISTRY = "registry.iotac.rid-intrasoft.eu/iotacregistry/"
      
      BRANCH_NAME = "master"
      DOCKER_IMAGE_TAG = "$APP_NAME:R${env.BUILD_ID}"
      
      VM_DEV01 = "116.203.5.132:2376"
      VM_DEV02 = "116.203.5.134:2376"
      VM_DEV01_IP = "116.203.5.132"
      VM_DEV02_IP = "116.203.5.134" 
      
      // SWVA_ADDRESS = "160.40.52.249:5007"
      // SWVA_PROJECT_PATH = "https://github.com/iotac-eu/honeypot"
      // SWVA_LANGUAGE = "Python"
      // SWVA_USERNAME = "julieeen"

      // ZAP_USER = "dev-server"
      // ZAP_ADDRESS = "116.202.190.143"     
      // ZAP_PROJECT_ID = "36865967"
    }

    stages {

      stage('Checkout') {
          steps {
              echo 'Checkout SCM'
              checkout scm
              checkout([$class: 'GitSCM',
                        branches: [[name: env.BRANCH_NAME]],
                        extensions: [[$class: 'CleanBeforeCheckout']],
                        userRemoteConfigs: scm.userRemoteConfigs
              ])
            }
        }

        stage('Perform SAST with SonarQube') {
          environment {
            scannerHome = tool 'SonarQube'
          }
          steps{
            withSonarQubeEnv(installationName: 'SonarIOTAC'){
              echo 'Starting Static Application Security Testing analysis using SonarQube'
              sh '${scannerHome}/bin/sonar-scanner -Dsonar.projectKey=honeypot -Dsonar.sources=. '
            }
          } 
        } 

        stage('Build Docker image') { 
            steps {
                echo 'Starting to build docker image'
                script {
                   def dockerImage = docker.build(ARTIFACTORY_DOCKER_REGISTRY + DOCKER_IMAGE_TAG)
                }
                // sh 'docker build -t "$ARTIFACTORY_DOCKER_REGISTRY$DOCKER_IMAGE_TAG" .' //
            }
        }

        stage ('Push image to Artifactory') {
            steps {
              withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'Artifacts', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) {
                  echo 'Login to Artifactory Registry'
                  sh "docker login --password='${PASSWORD}' --username=${USERNAME} ${ARTIFACTORY_SERVER}"

                  echo 'Pull image with Build-ID'
                  sh 'docker push "$ARTIFACTORY_DOCKER_REGISTRY$DOCKER_IMAGE_TAG"'

                  echo 'Logout from Registry'
                  sh 'docker logout $ARTIFACTORY_SERVER'
              }
            }
        }

        stage('Remove Image from CI Server') {
          steps {
                sh 'docker rmi "$ARTIFACTORY_DOCKER_REGISTRY$DOCKER_IMAGE_TAG"'
            }
        }

         stage('Undeploy Earlier Container') {
          steps{
            script {
              docker.withServer("$VM_DEV01", 'vm-dev01-creds') {
                    echo 'Stop and Remove Container from Earlier Build'
                    sh 'docker stop $APP_NAME || true && docker rm $APP_NAME || true'
              }
            }
          }
        }



        // stage('Perform System-Wide Vulnerability Assessment') {
        //   steps {
        //     script {
        //       try {
        //           echo 'Starting System-Wide Vulnerability Assessment analysis'
        //           sh " curl --max-time 1 -X GET \'http://${SWVA_ADDRESS}/MultiModuleVulnerabilityPrediction/VulnerabilityAssessment?project_path=${SWVA_PROJECT_PATH}&language=${SWVA_LANGUAGE}&user_name=${SWVA_USERNAME}\' "
        //       } 
        //       catch (err) {
        //           echo err.getMessage()
        //       }
        //     }
        //   }
        // }         
   
        
        stage('Deploy Image') {
          steps{
            script {
              docker.withServer("$VM_DEV01", 'vm-dev01-creds') {
                withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 'Artifacts', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD']]) {
                    echo 'Login to Artifactory Registry'
                    sh "docker login --password='${PASSWORD}' --username=${USERNAME} ${ARTIFACTORY_SERVER}"

                    echo 'Pull image with Build-ID'
                    sh 'docker pull "$ARTIFACTORY_DOCKER_REGISTRY$DOCKER_IMAGE_TAG"'

                    echo 'Deploy image to VM'
                    sh 'docker run -d --label io.portainer.accesscontrol.teams=iotacdevs --name "$APP_NAME" "$ARTIFACTORY_DOCKER_REGISTRY$DOCKER_IMAGE_TAG"'

                    echo 'Logout from Registry'
                    sh 'docker logout $ARTIFACTORY_SERVER'
                }
              }
            }
          }
        }

       // stage('Perform DAST with OWASP ZAP') {
       //      steps {
       //          echo 'Starting Dynamic Application Security Testing analysis using OWASP ZAP'
       //          sshagent(credentials : ['OwaspZapSSH']) {
       //            //sh "ssh ${ZAP_USER}@${ZAP_ADDRESS} -C \'python3 /dast/start_dynamic_analysis.py -t http://${VM_DEV01_IP}:8080 -b $env.BRANCH_NAME -p ${ZAP_PROJECT_ID} \'"
       //            sh "ssh ${ZAP_USER}@${ZAP_ADDRESS} -C \' ls \'"
       //          }
       //      }
       //  }

    }
}