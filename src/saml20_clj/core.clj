(ns saml20-clj.core
  "Main interface for saml20-clj SP functionality. The core functionality is broken out into several separate
  namespaces, but vars are made available here via Potemkin."
  (:require [potemkin :as p]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.crypto :as crypto]
            [saml20-clj.encode-decode :as encode]
            [saml20-clj.sp.metadata :as metadata]
            [saml20-clj.sp.request :as request]
            [saml20-clj.sp.response :as response]
            [saml20-clj.state :as state]))

;; this is so the linter doesn't complain about unused namespaces.
(comment
  coerce/keep-me
  crypto/keep-me
  encode/keep-me
  metadata/keep-me
  request/keep-me
  response/keep-me
  state/keep-me)

(p/import-vars
 [coerce
  ->X509Certificate
  ->Response
  ->xml-string]

 [crypto
  has-private-key?]

 [encode
  str->base64
  base64->str]

 [metadata
  metadata]

 [request
  idp-redirect-response
  request]

 [response
  decrypt-response
  assertions
  default-validation-options
  validate]

 [state
  record-request!
  accept-response!
  in-memory-state-manager])
