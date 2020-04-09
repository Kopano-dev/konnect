#!/usr/bin/env groovy

pipeline {
	agent {
		dockerfile {
			filename 'Dockerfile.build'
		}
	}
	stages {
		stage('Bootstrap') {
			steps {
				echo 'Bootstrapping..'
				sh 'go version'
				sh 'yarn -v'
				sh 'node -v'
			}
		}
		stage('Lint') {
			steps {
				echo 'Linting..'
				sh 'make lint-checkstyle GOLINT_ARGS="--new-from-rev=HEAD~ --verbose"'
				checkstyle pattern: 'test/tests.lint.xml', canComputeNew: false, unstableTotalAll: '50'
				checkstyle pattern: 'test/tests.eslint.xml', canComputeNew: false, failedTotalAll: '5', unstableTotalAll: '50'
			}
		}
		stage('Test') {
			steps {
				echo 'Testing..'
				sh 'make test-xml-short'
				junit allowEmptyResults: false, testResults: 'test/tests.xml'
			}
		}
		stage('Vendor') {
			steps {
				echo 'Fetching vendor dependencies..'
				sh 'make vendor'
			}
		}
		stage('Build') {
			steps {
				echo 'Building..'
				sh 'make DATE=reproducible'
				sh './bin/konnectd version && sha256sum ./bin/konnectd'
			}
		}
		stage('Test with coverage') {
			steps {
				echo 'Testing with coverage..'
				sh 'make test-coverage COVERAGE_DIR=test/coverage.jenkins || true'
				publishHTML([allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true, reportDir: 'test/coverage.jenkins', reportFiles: 'coverage.html', reportName: 'Go Coverage Report HTML', reportTitles: ''])
				step([$class: 'CoberturaPublisher', autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: 'test/coverage.jenkins/coverage.xml', failUnhealthy: false, failUnstable: false, maxNumberOfBuilds: 0, onlyStable: false, sourceEncoding: 'ASCII', zoomCoverageChart: false])
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
			cleanWs()
		}
	}
}
