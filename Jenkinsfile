#!/usr/bin/env groovy

pipeline {
	agent {
		docker {
			image 'golang:1.13.4'
			args '-u 0'
		 }
	}
	environment {
		DEP_RELEASE_TAG = 'v0.5.4'
		GOBIN = '/usr/local/bin'
		DEBIAN_FRONTEND = 'noninteractive'
	}
	stages {
		stage('Bootstrap') {
			steps {
				echo 'Bootstrapping..'
				sh 'curl -sSL -o $GOBIN/dep https://github.com/golang/dep/releases/download/$DEP_RELEASE_TAG/dep-linux-amd64 && chmod 755 $GOBIN/dep'
				sh 'go get -v golang.org/x/lint/golint'
				sh 'go get -v github.com/tebeka/go2xunit'
				sh 'apt-get update && apt-get install -y gettext-base imagemagick python-scour'
			}
		}
		stage('Yarn') {
			steps {
				echo 'Installing Yarn..'
				sh 'apt-get update && apt-get install -y apt-transport-https'
				sh 'curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -'
				sh 'echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list'
				sh 'curl -sL https://deb.nodesource.com/setup_10.x | bash -'
				sh 'apt-get install -y yarn'
			}
		}
		stage('Lint') {
			steps {
				echo 'Linting..'
				sh 'make lint | tee golint.txt || true'
				sh 'make vet | tee govet.txt || true'
			}
		}
		stage('Build') {
			steps {
				echo 'Building..'
				sh 'make DATE=reproducible'
				sh './bin/konnectd version && sha256sum ./bin/konnectd'
			}
		}
		stage('Test') {
			steps {
				echo 'Testing..'
				sh 'make test-xml-short'
			}
		}
		stage('Dist') {
			steps {
				echo 'Dist..'
				sh '$(git diff --stat)'
				sh 'test -z "$(git diff --shortstat 2>/dev/null |tail -n1)" && echo "Clean check passed."'
				sh 'make check'
				sh 'make dist'
			}
		}
	}
	post {
		always {
			archiveArtifacts 'dist/*.tar.gz'
			junit allowEmptyResults: true, testResults: 'test/*.xml'
			warnings parserConfigurations: [[parserName: 'Go Lint', pattern: 'golint.txt'], [parserName: 'Go Vet', pattern: 'govet.txt']], unstableTotalAll: '0'
			cleanWs()
		}
	}
}
