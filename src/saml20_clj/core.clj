(ns saml20-clj.core
  "Main interface for saml20-clj SP functionality. The core functionality is broken out into several separate
  namespaces, but vars are made available here via Potemkin."
  (:require [potemkin :as p]
            [saml20-clj
             [coerce :as coerce]
             [state :as state]]
            [saml20-clj.sp
             [request :as request]
             [response :as response]]))

;; this is so the linter doesn't complain about unused namespaces.
(comment
  coerce/keep-me
  request/keep-me
  response/keep-me
  state/keep-me)

(p/import-vars
 [coerce
  ->Response
  ->xml-string]

 [request
  idp-redirect-response
  metadata
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
