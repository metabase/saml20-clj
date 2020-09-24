(ns saml20-clj.sp
  "Main interface for saml20-clj SP functionality. The core functionality is broken out into several separate
  namespaces, but vars are made available here via Potemkin."
  (:require [potemkin :as p]
            [saml20-clj.sp
             [request :as request]
             [response :as response]]))

(comment
  request/keep-me
  response/keep-me)

(p/import-vars
 [request
  bump-saml-id-timeout!
  create-request
  create-request-factory
  generate-mutables
  get-idp-redirect
  metadata
  next-saml-id!
  prune-timed-out-ids!]

 [response
  parse-response
  decrypt-response
  response-status
  assertions
  assert-valid-signatures])
