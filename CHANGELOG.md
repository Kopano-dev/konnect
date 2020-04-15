# CHANGELOG

## Unreleased



## v0.32.0 (2020-04-15)

- Implement delegation of end session to external authority
- Improve names of temporary state and consent cookies
- Use correct path when removing state cookies
- Store identified user external authority ID in session data
- Implement redirect binding slo response


## v0.31.0 (2020-04-09)

- Relax linter to let more warning pass
- Implement validation for IdP initiated SLO requests
- Add support for expiration and session id for external authorities
- Fix wrong error message when there was no error
- Add additional TODO markers for SAML external authority
- Improve logging when using external SAML authority
- Retry SAML initialize on error
- Improve OIDC endsession endpoint handler when without token hint
- Implement support for SAML IdP slo
- Fail early when SAML2 authority fails to resolve user from backend
- Apply user mapping when resolving users from LDAP backend
- Update 3rd party dependencies
- Update license ranger and generate 3rd party licenses from vendor folder


## v0.30.0 (2020-03-09)

- Add SAML2 external authority example config
- Update linter in CI to latest version so it works with Go 1.14
- Implement SAML2 external authority support
- Prepare external authority support for different authority types
- Update and deduplicate external dependencies
- Ensure identifier client index.html is actually loaded
- Build with Go 1.14
- Merge branch 'IljaN-make-identifier-webapp-optional'
- Add disable-identifier-webapp option
- Migrate konnect identifier to newly introduced theme.spacing api


## v0.29.0 (2020-02-13)

- Detect browser state change issues
- Add fulllint helper to lint from the start
- Update 3rd party Go dependencies
- Update javascript 3rd party dependencies
- Reorganize component folder structure
- Remove webkit autofill hack
- Update license parser to support esm sub modules
- Reorganize identifier webapp
- Update c-r-a, kpop and dependencies
- Clean up linter warnings
- Merge branch 'embedding' of https://github.com/IljaN/konnect
- Merge branch 'bugfix/dynamic-port-redirect-native-clients' of https://github.com/DeepDiver1975/konnect
- Make konnect usable as library
- Only lint changes, to increase visibility of newly introduced issues
- Allow dynamic ports in redirect uri for native clients
- Add build arg for explict version selection for Docker build
- Update third party dependencies
- Fix unhandled error
- Log initialiation error when external auth fails to initialize
- Fix spelling mistakes


## v0.28.1 (2019-12-16)

- Update oidc-go to fix pkce Base64URL padding


## v0.28.0 (2019-12-02)

- Update third party modules
- Update kcc-go to v5


## v0.27.0 (2019-11-25)

- Relax linting requirement
- Update dependencies to their latest minor releases
- Update 3rd party dependencies
- Use Go modules instead of Go dep
- Set SameSite=None for all cookies
- Build with Go 1.13.4


## v0.26.0 (2019-11-11)

- Strip issuer subpath for OIDC url endpoints
- Force prompt=none for sencodary authorize after external authority auth
- Avoid error when identifier backend resolve cannot find a user
- Update curl to fix building of container image
- Build with Go 1.13.3


## v0.25.3 (2019-10-23)

- Fix cookie backend claims context
- Ensure BASE in fmt and check targets
- Add a list of technologies used


## v0.25.2 (2019-09-30)

- Build with Go 1.13.1


## v0.25.1 (2019-09-11)

- Update Docker entrypoint for metrics listener
- Expose metrics port for Docker containers


## v0.25.0 (2019-09-11)

- Build with Go 1.13 and update minimal Go version to 1.13
- Add usage survey block to README
- Add automatic survey reporting
- Add basic metrics


## v0.24.2 (2019-09-05)

- Merge pull request [#112](https://stash.kopano.io/projects/KC/repos/konnect/issues/112/) in KC/konnect from ~GITCOMMIT/konnect:master to master


## v0.24.1 (2019-09-04)

- Enable Icelandic translation, and avoid loading untranslated catalogs
- Update kpop to 0.24.5
- Translated using Weblate (Icelandic)
- Add args to changelog target
- Update kpop to 0.20.4
- Update list of enabled languages
- Add Hindi
- rename language
- Translated using Weblate (Dutch)
- Translated using Weblate (Russian)
- Translated using Weblate (Norwegian Bokmål)
- Translated using Weblate (French)
- Translated using Weblate (Portuguese (Portugal))
- Translated using Weblate (Portuguese (Portugal))
- Translated using Weblate (Norwegian Bokmål)
- Translated using Weblate (Russian)
- Cleanup Dockerfile
- Fixup headlines


## v0.24.0 (2019-07-10)

- Update dep to v0.5.4
- Update kcc-go and dependencies


## v0.23.6 (2019-07-09)

- Add healthcheck success output
- Update Dockerfiles for best practices
- Avoid trying to load a key with empty filename
- Add healthcheck sub command
- Bump diff from 3.4.0 to 3.5.0 in /identifier
- Handle redirect_uri parse error in client registration


## v0.23.5 (2019-06-12)

- Update kcc-go to 4.0.0 (and dependencies)
- Use Apache-2.0 license
- Deduplicate yarn.lock
- Bump handlebars from 4.0.11 to 4.1.2 in /identifier
- Bump clean-css from 4.1.9 to 4.1.11 in /identifier
- Bump axios from 0.16.2 to 0.18.1 in /identifier
- Bump sshpk from 1.13.1 to 1.16.1 in /identifier


## v0.23.4 (2019-05-21)

- Avoid breaking on startup when starting with empty scopes definitions


## v0.23.3 (2019-05-10)

- Fix a problem where welcome page would not display


## v0.23.2 (2019-05-10)

- Avoid remove of empty keyframes for autoFill detection
- Properly detect Chrome auto fill in login form fields


## v0.23.1 (2019-05-09)

- Use correct dep download URL
- Ensure JSON translations are not empty on fresh build
- Build with Go 1.12 and use latest dep tool


## v0.23.0 (2019-05-09)

- Update js license ranger to include notices
- Optimize use of visual white space
- Update kpop and migrage typography to new variants
- Enable nl and ru languages in production build
- Translated using Weblate (Dutch)
- Rebuild translation catalogs
- Add stats target for i18n
- Rebuild translations and translate to German
- Make it possible to translate built in scope descriptions
- Always allow merge to run
- Add language selector
- Only leave actually translated languages enabled in production builds
- Merge translation files and fix German typos
- Update kpop
- Correctly register pt-PT
- Update kpop and react-scripts
- Slightly imporve Material-UI styles
- Update react-router to 5.0.0
- Update Material-UI dependency to latest
- Update React to 18.8.6
- Do not start browser when in dev mode
- Replace __PATH_PREFIX__ with sane value in dev mode
- Change license to Apache License 2.0


## v0.22.0 (2019-04-26)

- Add origins key to web client examples
- Add hint that Konnect has learned to load JSON Web Keys
- Update external Kopano dependencies
- Include NOTICE files in 3rdparty-LICENSES.md
- Log default OIDC provider signing details
- Implement support for EdDSA keys
- Fix typos
- Add TLS client auth support for kc backend
- Setup kcc default HTTP client
- Unify HTTP client settings and setup
- Add support to set URI base path
- Translated using Weblate (Portuguese (Portugal))
- Translated using Weblate (Norwegian Bokmål)
- Translated using Weblate (Russian)
- Update Go dependencies
- Add threadsafe authority discovery support
- Only log unhandled inner identity manager errors
- Only compare hostname (not the port) for native clients
- Only enable default external authority
- Fixup yaml config
- Set RSA-PSS salt length for all RSA-PSS JWT algs always
- Add OAuth2 RP support to identifier
- Add examples for remove debugging and IDE
- Ignore debug build results
- Ignore .vscode for people using it
- Integrate Delve debugger support via `make dlv`
- Use Go report card batch
- Add Go report card
- Add godoc entry point with import annotation
- Improve docs, mark cookie backend as testing only
- Add reference for OpenID Connect dynamic client registration spec


## v0.21.0 (2019-03-24)

- Add dynamic client registration configuration support
- Validate client secrets of dynamically registered clients
- Add commandline parameter to allow dynamic client registration
- Use prefix to identitfy dynamic clients ids
- Properly pass on claims scopes on auth redirect
- Implement OpenID Connect Dynamic Client Registration 1.0
- Add cross references to implemented standards


## v0.20.0 (2019-03-15)

- Add support for preferred_username claim
- Implement PKCE code challenges as defined in RFC 7636
- Add support for konnect/id scope with LDAP backends
- Make LDAP subject source configurable
- Improve DN to sub conversion to clarify code
- Fix up --use parameter in jwk-from-pem util
- update Alpine base


## v0.19.1 (2019-02-06)

- Show details and print OK for make check
- Add client guest flag to configuration and bin script


## v0.19.0 (2019-02-06)

- Include registration and scopes yaml examples in dist tarball
- Make OIDC authorize session available early
- Add utils sub command for pem2jwk conversion
- Correct some spelling errors in configuration comments
- Support trust for trusted clients using guest identity
- Support trusted client scopes in secure oidc request


## v0.18.0 (2019-01-22)

- Bring back mandatory identity claims for ldap identifier backend
- Allow startup without guest manager
- Allow empty user claims in identifier
- Cleanup identifier logon claims and comments
- Bump base copyright years to 2019
- Build with Node 10
- Migrate from Glide to Dep
- Use blake2b implementation from golang.org/x/crypto


## v0.17.0 (2019-01-22)

- Konnect now requires Go 1.10
- Add sanity checks for user entry IDs
- Support internal claims for identifier backends
- Add multi server support for kc backend
- Add support to return request provided claims in ID token and userinfo
- Add possibility to pass thru claims from request to tokens
- Add request claims as authorized claims for all managers
- Add jti claim to access and refresh tokens
- Add OIDC endsession support for guest users via session
- Support guest users via signed claims authorize request
- Add OIDC invalid_request_object error and use accordingly
- Add support for the auth_time OIDC claim request
- Add validation for the sub requested claim
- OIDC authorize claims parameter support (1/2)
- OIDC authorize claims parameter support (1/2)
- Add support for client jwks in client registartion
- Implement support for request objects with OIDC authorize
- Always offer all supported ID token signing alg values


## v0.16.1 (2018-11-30)

- Fix startup problem without scopes conf


## v0.16.0 (2018-11-30)

- Extend identifier API docs by added fields of hello response
- Report and allow scopes which are configured in scopes conf
- Add new scopes configuration file to config and bin script
- Add scopes.yaml configuration file
- Move scope meta data to backend
- Consolidate publicate scope definition
- Log correct error after SSOLogon response


## v0.15.0 (2018-10-31)

- docs: Add OpenAPI 3 specification for the Konnect Identifier REST API
- Translated using Weblate (German)
- build: Fetch and include identifier 3rd party licenses in dist
- Use Go 1.11 in Jenkins
- identifier: Full German translation
- Add a bunch of languages for translation
- Fixup gofmt
- identifier: Add i18n support for dynamic error messages
- identifier: Add i18n for identifier web app
- identifier: Add gear for i18n
- identifier: Make identifier screens responsive
- Remove docs not relevant for konnect


## v0.14.4 (2018-10-16)

- Use archiveArtifacts instead of deprecated archive step
- Use golint from new location
- identifier: Allow unset of logon cookie without user
- ldap: Compare LDAP attributes case insensitive


## v0.14.3 (2018-09-28)

- Update build checks
- Update yarn.lock


## v0.14.2 (2018-09-28)

- scripts: Reverse signing_kid check
- scripts: Ensure correct owner when creating paths


## v0.14.1 (2018-09-26)

- Remove obsolete use of external environment files
- Fix possible race in session cleanup


## v0.14.0 (2018-09-21)

- Refuse to start with low exponent RSA keys in RS signing mode
- Use RSA-PSS (PS256) as JWT alg by default


## v0.13.1 (2018-09-19)

- oidc: Use correct Salt length with RSA-PSS signatures


## v0.13.0 (2018-09-17)

- oidc, identifier: Use kcoidc auth to kc for kc sessions


## v0.12.0 (2018-09-12)

- oidc: Allow change of signing method
- oidc: Allow additional validations keys
- Integrate kc session support to docs and scripts
- identifier: Add configuration for kc session timeout
- identifier, oidc: Add support for backend identity provider sessions
- Update svg syntax
- identifier: Set random NONCE in CSP and HTML
- Add missing session API endpoint to Caddyfile examples


## v0.11.2 (2018-09-07)

- smaller typo corrections


## v0.11.1 (2018-09-07)

- Fix end session endpoint subject verify
- Remove forgotten debug


## v0.11.0 (2018-09-06)

- oidc: Make subject URL safe by default
- identifier: Update react-scripts to 1.1.5
- oidc: Implement `sid` ID Token claim
- oidc: Implement browser state and session state
- Increase no-file limit to infinite


## v0.10.2 (2018-08-29)

- identifier: Use new favicon built from svg
- identifier: Update to kpop 0.9.2 and dependencies
- provider: Ensure to verify authentication request


## v0.10.1 (2018-08-21)

- Add setup subcommand to binscript


## v0.10.0 (2018-08-17)

- Include scripts in dist tarball
- Run Jenkins with Go 1.10
- Add log-level to config and avoid double timestamp for systemd
- Add commandline args for log output control
- Add systemd unit with runner script and config
- Move rkt exaples to README


## v0.9.0 (2018-08-01)

- identifier: Add some TODO comments
- oidc: Add support for additional claims in ID Token
- oidc: Return scope value with authorize response
- oidc: Add support for additional userinfo claims


## v0.8.0 (2018-07-27)

- oidc: Add support for url-safe sub via scope


## v0.7.0 (2018-07-17)

- Remove redux debug logging from production builds
- Use PureComponent in base app
- Update to kpop 0.5 and Material-UI 1
- identifier: Add text labels for new scopes
- Implement scope limitation
- Remove debug
- Cleanup scope structs
- oidc: Add all claims to context


## v0.6.0 (2018-05-28)

- Add checks and consent to end session support
- Allow configuration of client secrets
- Implement endsession endpoint
- identifier: Fix undefined link in consent screen
- identifier: Update style to kpop and kopanoBlue
- identifier: Remove tap plugin
- identifier: Use kpop components
- identifier: Add autoComplete attribute to login
- identifier: Add build version information and favicon
- identifier: Bump React and Material-UI versions


## v0.5.5 (2018-04-11)

- Add identifier-registration parameter to services


## v0.5.4 (2018-04-09)

- provider: Support redirect_uri values with query


## v0.5.3 (2018-04-05)

- identifier: Use correct no_uid_auth flag for logon to kc


## v0.5.2 (2018-04-04)

- docker: Allow Docker to switch user at runtime
- docker: Make it possible to load secrets from custom location
- identifier: Use no_uid_auth flag for logon to kc
- Remove forgotten debug logging


## v0.5.1 (2018-03-23)

- Docker: Support additional ARGS via environment
- Add hints for unix user required for kc backend
- Fix Docker examples so they actually work


## v0.5.0 (2018-03-16)

- server: Disable HTTP request log by default
- Add instructions for client registry conf
- identifier: Add Client registry and validation
- fix link to openid spec
- Use port 3001 for development
- Update build parameters for Go 1.10 compatibility
- Update README to include Docker and dependencies
- Update to Go 1.9 and Glide 0.13.1
- Add 3rd party license information
- Never fail on junit in post state
- Do not run lint on normal build
- Fixed a typo (Konano > Kopano)


## v0.4.1 (2018-02-09)

- provider: Allow the OAuth2 token flow
- identifier: Fix select_account mode
- Update release download link
- Fill default parameters for cookie backend


## v0.4.0 (2018-01-30)

- Add Dockerfile.release
- Add Dockerfile
- identifier: Use properties to retrieve userdata
- fix typo on readme
- identifier: Implement family_name and given_name
- identifier: Add UUID decode support to ldap uuid
- identifier: LDAP descriptors are case insensitive
- identifier: Implement uuid attribute support
- identifier: Clean data from store on logoff
- identifier: add overlay support with message
- identifier: use augmenting teamwork background only
- identifier: Update background to augmenting teamwork
- identifier: Properlu handle LDAP search not found
- identifier: Properly handle LDAP bootstrap errors


## v0.3.0 (2018-01-12)

- Refactor bootstrap/launch code
- Add support for auth_time claim in ID Token
- Update example scripts to use the new parameters
- Remove --insecure parameter from examples
- Remove double claim validation
- identifier: Remove re-logon without password
- Add support to load PKCS[#8](https://stash.kopano.io/projects/KC/repos/konnect/issues/8/) keys
- Load all keys from file
- Add support for trusted proxies
- identifier: Store logon time and validate max age
- identifier: Add LDAP rate limiter
- identifier: Implement LDAP backend
- Add comments about authorized scopes
- Make older golint happy
- Update README
- Fix whitespace in Caddyfiles
- Identifier: use SYSTEM as KC username default
- Update Caddyfile to be a real example
- Use unpadded Base64URL encoding for left-most hash
- Update docs to reflect plugin
- Add API overview graph
- Disable service worker
- Integrate redux into service worker


## v0.2.2 (2017-11-29)

- Fix URLs extrated from CSS


## v0.2.1 (2017-11-29)

- Remove v prefix from version number


## v0.2.0 (2017-11-29)

- Bump up Loading a litte so it fits on low height screens better
- Use inline blurred svg thumbnail background
- Use webpack with code splitting
- Fix support for service worker fetching index.html
- Report additional supported scopes
- Allow CORS for discovery docs
- Build identifier webapp by default
- Include idenfier webapp in dist
- Fixup systemd service
- Add Makefile for identifier client
- Update rkt builder and services for kc backend
- Add implicit trust for clients on the iss URI
- Fixup identifier HTML page server routes
- Add secure default CSP to HTML handler
- Fixup: loading is now a string, no longer bool
- Handle offline_access scope filtering
- Add support to show multiple scopes
- Use redirect as component
- Allow identifier users to be included in tokens
- Split up stuff into multiple files
- Use unique component class names
- Allow identifier users to be included in tokens
- Add some hardcoded clients for testing
- Reset errors and loading from choose to login
- Set prompt=none when identifier is done
- Fix prompt=login login
- Implement proper loading state for consent ui
- Implement consent cancel
- Properly retrieve and pass through displayName
- Only show account selector when prompt requests it
- WIP: implement consent via direct identifier flows


## v0.1.0 (2017-11-27)

- Only allow continue= values which begin with location.origin
- Update README for backends
- Ignore no-cookie error
- Add support for Firefox
- Implement welcome screen and logoff ui
- Set Referer-Policy header
- Split up the monster
- Move hardcoded defaults to config
- Add logoff API endpoint
- Add cookie checks for logon and hello
- Fix linter errors and unit tests
- Move general code to utils
- Implement identifier and kc backend
- Move config to seperate package
- Ignore /examples folder
- Merge pull request [#6](https://stash.kopano.io/projects/KC/repos/konnect/issues/6/) in KC/konnect from ~SEISENMANN/konnect:longsleep-jenkinsfile to master
- Add Jenkinsfile
- Add aci builder and systemd service


## v0.0.1 (2017-10-02)

- Add docs abourt key and secret parameter
- Fix README to use correct bin location
- Merge pull request [#5](https://stash.kopano.io/projects/KC/repos/konnect/issues/5/) in KC/konnect from ~SEISENMANN/konnect:longsleep-kw-sign-in to master
- Add support for KW sign-in form
- Merge pull request [#4](https://stash.kopano.io/projects/KC/repos/konnect/issues/4/) in KC/konnect from ~SEISENMANN/konnect:longsleep-use-lowercase-cmdline-params to master
- Use only lower case commandline arguments
- Merge pull request [#3](https://stash.kopano.io/projects/KC/repos/konnect/issues/3/) in KC/konnect from ~SEISENMANN/konnect:longsleep-use-external-rndm to master
- Use rndm from external module
- Build static without cgo by default
- Add Makefile
- Use seperate listener, add log message when listening started
- Put local imports last
- Use build date in version command
- Add X-Forwarded-Prefix to Caddyfile
- Merge pull request [#2](https://stash.kopano.io/projects/KC/repos/konnect/issues/2/) in KC/konnect from ~SEISENMANN/konnect:longsleep-caddyfile to master
- Add example Caddyfile
- Move random helpers to own subpackage
- Merge pull request [#3](https://stash.kopano.io/projects/KC/repos/konnect/issues/3/) in ~SEISENMANN/konnect from longsleep-konnect-id-scope to master
- Implement konnect/id scope
- Update dependencies
- Enable code flows in discovery document
- Support --secret parameter value as hex
- Update README with newly added parameters
- Support identity claims in refresh tokens
- Merge pull request [#1](https://stash.kopano.io/projects/KC/repos/konnect/issues/1/) in ~SEISENMANN/konnect from longsleep-encrypt-cookies-in-at to master
- Add encryption manager
- Use nacl.secretbox for cookies encryption
- Prepare encryption of cookies value in at
- Move refresh token implementation to konnect
- Move kc claims to konnect package
- Remove obsolete OPTION handler
- Add support for insecure TLS client connections
- Fix typo in example users - sorry Ford, i thought you were perfect
- Add option to limit cookie pass through to know names
- Store cookie value in access token
- Add jwks.json endpoint
- Use subject as user id identifier everywhere
- Add userinfo endpoint with cors
- Add token endpoint with cors
- Implement code flow support
- Use cookies and users compatible with minioidc
- Add support for sub path reverse proxy mode
- Add Python and YAML to .editorconfig
- Add cookie backend support
- Add cookie identity manager
- Add more commandline flags
- Add key loading
- Add unit tests for provider
- Remove forgotten debug
- Refactor server launch code
- Prepare serve code refactorization
- Simplify
- Add dummy user backend for testing
- Add .well-known discovery endpoint
- Add OIDC basic implementation including authorize endpoint
- Add references to other implementations
- Use glide helper for unit tests
- Add health-check handler with unit tests
- Add minimal README, tl;dr only for now
- Add vendoring and dependency locks with Glide
- Add initial server stub with commandline flags, logger and version
- Initial commit

