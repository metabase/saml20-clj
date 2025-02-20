# saml20-clj

[![Downloads](https://versions.deps.co/metabase/saml20-clj/downloads.svg)](https://versions.deps.co/metabase/saml20-clj)
![Linters](https://github.com/metabase/saml20-clj/actions/workflows/linters.yml/badge.svg)
![Tests](https://github.com/metabase/saml20-clj/actions/workflows/tests.yml/badge.svg)
![Release](https://github.com/metabase/saml20-clj/actions/workflows/release.yml/badge.svg)
[![codecov](https://codecov.io/gh/metabase/saml20-clj/branch/master/graph/badge.svg)](https://codecov.io/gh/metabase/saml20-clj)
[![License](https://img.shields.io/badge/license-Eclipse%20Public%20License-blue.svg)](https://raw.githubusercontent.com/metabase/saml20-clj/master/LICENSE)
-[![cljdoc badge](https://cljdoc.org/badge/metabase/saml20-clj)](https://cljdoc.org/d/metabase/saml20-clj/CURRENT)

[![Clojars Project](https://clojars.org/metabase/saml20-clj/latest-version.svg)](http://clojars.org/metabase/saml20-clj)


This is a SAML 2.0 Clojure library for SSO acting as a thin wrapper around the Java libraries [OpenSAML
v4](https://wiki.shibboleth.net/confluence/display/OS30/Home) and some utility functions from [OneLogin's SAML
library](https://github.com/onelogin/java-saml) This library allows a Clojure application to act as a Service Provider
(SP).

### Important note!

The underlying Java library, OpenSAML, is no longer available in Maven Central, so you'll have to add the repository
yourself. `deps.edn` example:

```clj
{:mvn/repos
 {"opensaml"{:url "https://build.shibboleth.net/nexus/content/repositories/releases/"}}}
 ```

## 2.0.0 Usage

### Creating metadata

In order for an identityprovider to understand you as a service-provider, you need to provide metadata about your
service. This is done in the following manner:

```clojure
(in-ns my-saml.core
  (:require [saml20-clj.core :as saml-core]
            [saml20-clj.coerce :as saml-coerce]))

(def config {:app-name "My Fancy App"
             :acs-url "https://my-app.com/saml/login"
             :slo-url "https://my-app.com/saml/logout"})

(def credentials {:alias "my-saml-secrets"
                  :filename "path/to/keystorefile.jks"
                  :password "s1krit"})

(def metadata (-> {:sp-cert (saml-coerce/->X509Certificate credentials)}
                  (merge config)
                  saml-core/metadata))
```

### Recording Requests

You can keep track of which requests are in flight to determine whether responses correspond to valid requests we've
issued and whether we've already got a response for a request (e.g. to replay attacks) by using a `StateManager`. This
library ships with a simple in-memory state manager suitable for a single instance, but you can create your own
implementation if you need something more sophisticated.

```clj
(require '[saml20-clj.core :as saml])

(def state-manager (saml/in-memory-state-manager))
```

### Logging In (SSO)

#### Requests

Basic usage for requests to the IdP looks like:

```clj
(require '[saml20-clj.core :as saml])

;; create a new request
(-> (saml/request
     {:sp-name          "My SP Name"
      :acs-url          "http://sp.example.com/demo1/index.php?acs"
      :idp-url          "http://idp.example.com/SSOService.php"
      :issuer           "http://sp.example.com/demo1/metadata.php"
      ;; state manager (discussed above) is optional, but if passed `request` will record the newly created request.
      :state-manager    state-manager
      ;; :credential is optional. If passed, sign the request with this key and attach public key data, if present
      :credential       sp-private-key})
    ;; create a Ring redirect response to the IDP URL; pass the request as base-64 encoded `SAMLRequest` query parameter
    (saml/idp-redirect-response ;; This is RelayState. In the old version of the lib it was encrypted. In some cases,
                                ;; like this it's not really sensitive so it doesn't need to be encrypted. Adding
                                ;; automatic encryption support back is on the TODO list
                                "http://sp.example.com/please/redirect/me/to/here"))
```

The `:credential` can be used to sign the request to the IdP, and attach any public key information (if present). It will happily accept several formats, depending on the use-case:
  - `private-key`: A PEM formatted string
  - `[public-cert private-key]`: A tuple containing an X509 Certificate and a private key, both in PEM format
  - `{:filepath "/path/to/keystore"
      :password "keystore-password"
      :alias    "key-alias"}`: A map describing a keystore and alias used.

#### Responses

Basic usage for responses from the IdP looks like this (assuming a Ring `request`):

```clj
(require '[saml20-clj.core :as saml])
(require '[saml20-clj.encode-decode :as saml-decode])

(-> request
    :params
    :SAML-response
    saml-decode/base64->str
    ;; Coerce the response to an OpenSAML `Response`. This can be anything from a raw XML string to a parsed
    ;; `org.w3c.dom.Document`
    saml/->Response
    ;; decrypt and validate the response. Returns decrypted response
    (saml/validate idp-cert sp-private-key options)
    ;; convert the Assertions to a convenient Clojure map so you can do something with them
    saml/assertions)
```

#### `validate` options

`validate` accepts an options map that allows you to configure what validations are done, as well as the
stateful parameters (if relevent) those validations are verified against. The list of options and their defaults are
shown below:

```clj
{ ;; e.g. "http://sp.example.com/demo1/index.php?acs" The assertion consumer service URL. It is *required*
 ;; always pass this value, as the SAML20 spec dictates that any Recipient field within a <SubjectConfirmationData>
 ;; must be checked against the :acs-url.
 :acs-url                      nil

 ;; The ID of the request we (the SP) sent to the IdP. ID is generated on our end, and should be something like a UUID
 ;; rather than a sequential number. If non-nil, the :in-response-to validator checks that <SubjectConfirmationData>
 ;; nodes have a value of InResponseTo that matches an ID.
 ;;
 ;; The state manager implementation that ships with this library does not keep request state; InResponseTo validation
 ;; is provided as an option in case you write your own more sophisticated implementation.
 :request-id                   (str (java.util.UUID/randomUUID))

 ;; If passed, must refer to an implementation of the StateManager protocol (either the built-in `in-memory-state-manager`
 ;; suitable for a single instance or a custom implementation suitable for your deployment). The StateManager, if enabled,
 ;; should record the `:request-id` and verify it against any returning response. Please refer to `state.clj` for implementation
 ;; details.

 ;; Note that enforcement of the `:state-manager` requires enabling the `:valid-request-id` response validator (which is
 ;; enabled by default).
 :state-manager		       nil

 ;; whether this response was solicited (i.e., in response to a request we sent to the IdP). If this is false, the
 ;; :in-response-to validator checks that the request-id is nil.
 :solicited?                   true

 ;; maximum amount of clock skew to allow for the :not-on-or-after and :not-before validators
 :allowable-clock-skew-seconds 180

 ;; address of the client. If set, the :address validator will check that <SubjectConfirmationData> nodes have an
 ;; Address matching this value *iff* Address is present. Address is optional attribute.
 :user-agent-address           nil

 ;; Unique identifier of the IdP. Also referred to as Entity ID or 'Issuer'. If passed, the `:issuer` validators will check
 ;; that the <Issuer> property for <Response> and <Assertion>s matches.
 :issuer                      nil

 ;; :response-validators and :assertion-validators are validation functions that run and check that the Response is
 ;; valid. If a check fails, these methods will throw an Exception. You can exclude some of these validators or add
 ;; your own by passing different values for these keys. Both types of validators are defined as multimethods; you can
 ;; add custom validators by adding more method implementations to their respective multimethods.

 ;; :response-validators are validation functions that run once for the entire Response. They are defined as
 ;; implementations of the saml20-clj.sp.response/validate-response multimethod.
 :response-validators (see below)


 ;; :assertion validators are validation functions that run against every Assertion in the response. They are defined
 ;; as implementations of saml20-clj.sp.response/validate-assertion.
 :assertion-validators (see below)
}
```

#### Default `:response-validators`

```clj
[;; If the <Response> itself is signed, verifies that this signature is matches the Response itself and matches the
 ;; IdP certificate. If Response is not signed, this validator does nothing.
 :signature

 ;; requires that either the <Response> is signed, *every* <Assertion> is signed.
 :require-signature

 ;; If the :issuer option is passed and <Response> has <Issuer> information, checks that these match.
 :issuer

 ;; validates the request ID with :state-manager if it is passed as an option. This does not validate that the value
 ;; matches InResponseTo -- that is done by :in-response-to.
 :valid-request-id]
```

#### Default `:assertion-validators`

```clj
[;; If <Assertion> is signed, the signature matches the Assertion and the IdP certificate. If <Assertion> is not
 ;; signed, this validator does nothing.
 :signature

 ;; If set, validation will ensure that all Assertions in the response are encrypted. If *any* unencrypted Assertions
 ;; are present, verification will fail
 :require-encryption

 ;; If :acs-url is non-nil, and <SubjectConfirmationData> is present, checks that <SubjectConfirmationData> has a
 ;; Recipient attribute matching this value.
 :recipient

 ;; If the :issuer option is passed, checks that Assertions have <Issuer> information and that it matches :issuer.
 :issuer

 ;; If <SubjectConfirmationData> is present, has a NotOnOrAfter attribute, and its value is in the future,
 ;; accounting for :allowable-clock-skew-seconds
 :not-on-or-after

 ;; If <SubjectConfirmationData> has a NotBefore attribute, checks that this value is in the past, accounting for
 ;; :allowable-clock-skew-seconds
 :not-before

 ;; If :request-id is non-nil and <SubjectConfirmationData> is present, checks that <SubjectConfirmationData> has an
 ;; InResponseTo attribute matching :request-id.
 :in-response-to

 ;; If :user-agent-address is non-nil and <SubjectConfirmationData> has an Address attribute, checks that Address
 ;; matches this value.
 :address]
```

### Logging Out (SLO)

#### Requests

Basic usage for logging out is to send the client a redirect to the IdP, with a LogoutResponse SAML message. This is
done in the following manner:

```clj
(request/idp-logout-redirect-response
  "Your SP Name"
  "logmeout@example.com" ;; the user's email
  "http://sp.example.com/demo1/metadata.php"
  (encode-decode/str->base64 "http://sp.example.com/demo1/metadata.php"))
  "my_random_id_42") ;; req-id is optional, and will get created for you.

```

Some clients will prefer that you send them the `SAMLRequest` as a query parameter, and they will handle the redirect, for that purpose you can use the `logout-redirect-location` function, which will include the `RelayState` and `SAMLRequest` as query parameters.

```clj
(request/logout-redirect-location
   {:issuer     "http://sp.example.com/demo1/metadata.php"
    :user-email "user@example.com"
    :idp-url    "http://idp.example.com/SSOService.php"
    :request-id "ONELOGIN_109707f0030a5d00620c9d9df97f627afe9dcc24"
    :relay-state (encode-decode/str->base64 "http://sp.example.com/demo1/metadata.php")})

;; =>
;; "http://idp.example.com/SSOService.php?SAMLRequest=fVLLbs<snip>&RelayState=aHR<snip>"
```

#### Responses

The IdP will redirect the client back to you, with a `SAMLResponse` in their query-params. You can validate this response by checking for the `SAMLResponse`'s `Status`.

## Differences from the original `saml20-clj` library

This repository is forked from [vlacs/saml20-clj](https://github.com/vlacs/saml20-clj), and at this point is more or less a complete re-write.

*  Other improvements:
   *  Uses OpenSAML v4 instead of OpenSAML v2 which was EOL'ed in 2016
   *  Tons of bug fixes, such as `saml20-clj.shared/base64->inflate->str` not actually calling `byte-inflate` at all
   *  Fixed millions of reflection warnings
   *  Removed duplicate functions
   *  Support for XML signing with SHA-256 instead of SHA-1, which is required by ADFS by default (via [k2n/saml20-clj](https://github.com/k2n/saml20-clj))
   *  Support for Clojure 1.10+
   *  Support for base-64 encodings that contain newlines
   *  Removed lots of dependencies on other libraries
   *  Reorganized code
   *  Removed tons of duplicate/unnecessary, untested code
   *  Fixed `<Assertion>` signatures not being validated
   *  Added Single Logout (SLO)

## License

* Copyright © 2013 VLACS <jdoane@vlacs.org>
* Copyright © 2017 Kenji Nakamura <kenji@signifier.jp>
* Copyright © 2019-2024 [Metabase, Inc.](https://metabase.com)

Distributed under the Eclipse Public License, the same as Clojure.
