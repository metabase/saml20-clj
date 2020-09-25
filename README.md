# saml20-clj

[![Downloads](https://versions.deps.co/metabase/saml20-clj/downloads.svg)](https://versions.deps.co/metabase/saml20-clj)
[![Dependencies Status](https://versions.deps.co/metabase/saml20-clj/status.svg)](https://versions.deps.co/metabase/saml20-clj)
[![Circle CI](https://circleci.com/gh/metabase/saml20-clj.svg?style=svg)](https://circleci.com/gh/metabase/saml20-clj)
[![codecov](https://codecov.io/gh/metabase/saml20-clj/branch/master/graph/badge.svg)](https://codecov.io/gh/metabase/saml20-clj)
[![License](https://img.shields.io/badge/license-Eclipse%20Public%20License-blue.svg)](https://raw.githubusercontent.com/metabase/saml20-clj/master/LICENSE)
[![cljdoc badge](https://cljdoc.org/badge/metabase/saml20-clj)](https://cljdoc.org/d/metabase/saml20-clj/CURRENT)

[![Clojars Project](https://clojars.org/metabase/saml20-clj/latest-version.svg)](http://clojars.org/metabase/saml20-clj)


This is a SAML 2.0 Clojure library for SSO acting as a fairly thin wrapper around the Java libraries [OpenSAML
v3](https://wiki.shibboleth.net/confluence/display/OS30/Home) and some utility functions from [OneLogin's SAML
library](https://github.com/onelogin/java-saml) This library allows a Clojure application to act as a Service Provider
(SP).

## 2.0.0 Usage

### Recording Requests

You can keep track of which requests are in flight to determine whether responses correspond to valid requests we've
issued and whether we've already got a response for a request (e.g. to replay attacks) by using a `StateManager`. This
library ships with a simple in-memory state manager suitable for a single instance, but you can create your own
implementation if you need something more sophisticated.

```clj
(require '[saml20-clj.core :as saml])

(def state-manager (saml/in-memory-state-manager))
```

### Requests

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
      ;; :private-key is optional. If passed, sign the request with this key
      :private-key      sp-private-key})
    ;; create a Ring redirect response to the IDP URL; pass the request as base-64 encoded `SAMLRequest` query parameter
    (saml/idp-redirect-response "http://idp.example.com/SSOService.php"
                                ;; This is RelayState. In the old version of the lib it was encrypted. In some cases,
                                ;; like this it's not really sensitive so it doesn't need to be encrypted. Adding
                                ;; automatic encryption support back is on the TODO list
                                "http://sp.example.com/please/redirect/me/to/here"))
```

### Responses

Basic usage for responses from the IdP looks like:

```clj
(require '[saml20-clj.core :as saml])

;; Coerce the response to an OpenSAML `Response`. This can be anything from a raw XML string to a parsed
;; `org.w3c.dom.Document`
(-> (saml/->Response xml)
    ;; decrypt and validate the response. Returns decrypted response
    (saml/validate idp-cert sp-private-key options)
    ;; convert the Assertions to a convenient Clojure map so you can do something with them
    saml/assertions)
```

`validate` accepts several options that let you configure what validations are done. The default options are:

```clj
{ ;; e.g. "http://sp.example.com/demo1/index.php?acs" The assertion consumer service URL. If this is not-nil, the
 ;; :recipient validator checks that <SubjectConfirmationData> nodes have a value of Recipient matching this value.
 :acs-url                      nil

 ;; The ID of the request we (the SP) sent to the IdP. ID is generated on our end, and should be something like a UUID
 ;; rather than a sequential number. If non-nil, the :in-response-to validator checks that <SubjectConfirmationData>
 ;; nodes have a value of InResponseTo that matches an ID.
 ;;
 ;; The state manager implementation that ships with this library does not keep request state; InResponseTo validation
 ;; is provided as an option in case you write your own more sophisticated implementation.
 :request-id                   nil

 ;; If passed, the state manager will
 :state-manager

 ;; whether this response was solicited (i.e., in response to a request we sent to the IdP). If this is false, the
 ;; :in-response-to validator checks that the request-id is nil.
 :solicited?                   true

 ;; maximum amount of clock skew to allow for the :not-on-or-after and :not-before validators
 :allowable-clock-skew-seconds 180

 ;; address of the client. If set, the :address validator will check that <SubjectConfirmationData> nodes have an
 ;; Address matching this value *iff* Address is present. Address is optional attribute.
 :user-agent-address           nil

 ;; :response-validators and :assertion-validators are validation functions that run and check that the Response is
 ;; valid. If a check fails, these methods will throw an Exception. You can exclude some of these validators or add
 ;; your own by passing different values for these keys. Both types of validators are defined as multimethods; you can
 ;; add custom validators by adding more method implementations to their respective multimethods.

 ;; :response-validators are validation functions that run once for the entire Response. They are defined as
 ;; implementations of the saml20-clj.sp.response/validate-response multimethod.
 :response-validators
 ;; The default Response validators are:

 [;; If the <Response> itself is signed, verifies that this signature is matches the Response itself and matches the
  ;; IdP certificate. If Response is not signed, this validator does nothing.
  :signature

  ;; requires that either the <Response> is signed, *every* <Assertion> is signed.
  :require-signature

  ;; validates the request ID with :state-manager if it is passed as an option. This does not validate that the value
  ;; matches InResponseTo -- that is done by :in-response-to.
  :valid-request-id]

 ;; :assertion validators are validation functions that run against every Assertion in the response. They are defined
 ;; as implementations of saml20-clj.sp.response/validate-assertion.
 :assertion-validators

 ;; The default Assertion validators are:
 [;; If <Assertion> is signed, the signature matches the Assertion and the IdP certificate. If <Assertion> is not
  ;; signed, this validator does nothing.
  :signature

  ;; If :acs-url is non-nil, and <SubjectConfirmationData> is present, checks that <SubjectConfirmationData> has a
  ;; Recipient attribute matching this value.
  :recipient

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
  :address]}
```

## Differences from the original `saml20-clj` library

This repository is forked from [vlacs/saml20-clj](https://github.com/vlacs/saml20-clj), and at this point is more or less a complete re-write.

*  Other improvements:
   *  Uses OpenSAML v3 instead of OpenSAML v2 which was EOL'ed in 2016
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

## License

* Copyright © 2013 VLACS <jdoane@vlacs.org>
* Copyright © 2017 Kenji Nakamura <kenji@signifier.jp>
* Copyright © 2019-2020 [Metabase, Inc.](https://metabase.com)

Distributed under the Eclipse Public License, the same as Clojure.
