# CHANGELOG

## Unreleased

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

