#!/usr/bin/env groovy

pipeline {
	agent {
		docker {
			image 'golang:1.8'
			args '-u 0'
		 }
	}
	environment {
		GLIDE_VERSION = 'v0.13.0'
		GLIDE_HOME = '/tmp/.glide'
	}
	stages {
		stage('Bootstrap') {
			steps {
				echo 'Bootstrapping..'
				sh 'curl -sSL https://github.com/Masterminds/glide/releases/download/$GLIDE_VERSION/glide-$GLIDE_VERSION-linux-amd64.tar.gz | tar -vxz -C /usr/local/bin --strip=1'
				sh 'go get -v github.com/golang/lint/golint'
				sh 'go get -v github.com/tebeka/go2xunit'
			}
		}
		stage('Lint') {
			steps {
				echo 'Linting..'
				sh 'golint \$(glide nv) | tee golint.txt || true'
				sh 'go vet \$(glide nv) | tee govet.txt || true'
			}
		}
		stage('Build') {
			steps {
				echo 'Building..'
				sh 'make'
				sh './bin/konnectd version'
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
				sh 'make dist'
			}
		}
	}
	post {
		always {
			archive 'dist/*.tar.gz'
			junit 'test/*.xml'
			warnings parserConfigurations: [[parserName: 'Go Lint', pattern: 'golint.txt'], [parserName: 'Go Vet', pattern: 'govet.txt']], unstableTotalAll: '0'
			cleanWs()
		}
	}
}
