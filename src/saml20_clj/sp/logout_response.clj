(ns saml20-clj.sp.logout-response
  "Handles parsing, validating and querying a LogoutResponse SAML message"
  (:require [saml20-clj.coerce :as coerce]
            [saml20-clj.sp.message :as message])
  (:import [org.opensaml.saml.saml2.core LogoutResponse StatusCode]
           org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder))

(defn logout-success?
  [^LogoutResponse response]
  (let [status-value (.. response getStatus getStatusCode getValue)]
    (= status-value StatusCode/SUCCESS)))

(def default-logout-validation-options
  {:response-validators [:signature
                         :issuer
                         :in-response-to
                         :require-authenticated]})

(defn validate-logout
  "Decode a ring request into a LogoutResponse SAML object and validate it.

  Throws if validation fails"
  (^LogoutResponse [req request-id issuer idp-cert]
   (validate-logout req {:issuer issuer
                  :idp-cert idp-cert
                  :request-id request-id}))
  (^LogoutResponse [req options]
   (let [options (-> (merge default-logout-validation-options options)
                     (assoc :request req :request-builder (LogoutRequestBuilder.)))
         {:keys [response-validators]} options]
     (when-let [msg-ctx (coerce/ring-request->MessageContext req)]
       (doseq [validator response-validators]
         (message/validate-message validator msg-ctx options))
       (coerce/->LogoutResponse msg-ctx)))))
