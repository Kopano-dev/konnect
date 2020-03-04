module stash.kopano.io/kc/konnect

go 1.13

require (
	github.com/crewjam/saml v0.4.0
	github.com/deckarep/golang-set v1.7.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/ghodss/yaml v1.0.0
	github.com/go-asn1-ber/asn1-ber v1.4.1 // indirect
	github.com/go-ldap/ldap/v3 v3.1.7
	github.com/golang/protobuf v1.3.3 // indirect
	github.com/google/go-querystring v1.0.0
	github.com/gorilla/mux v1.7.4
	github.com/gorilla/schema v1.1.0
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/longsleep/go-metrics v0.0.0-20191013204616-cddea569b0ea
	github.com/mendsley/gojwk v0.0.0-20141217222730-4d5ec6e58103
	github.com/orcaman/concurrent-map v0.0.0-20190826125027-8c72a8bb44f6
	github.com/prometheus/client_golang v1.4.1
	github.com/rs/cors v1.7.0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/crypto v0.0.0-20200210222208-86ce3cb69678
	golang.org/x/net v0.0.0-20200202094626-16171245cfb2
	golang.org/x/sys v0.0.0-20200212091648-12a6c2dcc1e4 // indirect
	golang.org/x/text v0.3.2 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0
	gopkg.in/square/go-jose.v2 v2.4.1
	gopkg.in/yaml.v2 v2.2.8
	stash.kopano.io/kgol/kcc-go/v5 v5.0.1
	stash.kopano.io/kgol/ksurveyclient-go v0.6.0
	stash.kopano.io/kgol/oidc-go v0.3.1
	stash.kopano.io/kgol/rndm v1.1.0
)

replace github.com/crewjam/httperr => github.com/crewjam/httperr v0.2.0
