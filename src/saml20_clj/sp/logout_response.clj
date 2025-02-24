(ns saml20-clj.sp.logout-response
  "Handles parsing, validating and querying a LogoutResponse SAML message"
  (:require [saml20-clj.coerce :as coerce]
            [saml20-clj.sp.response :as response])
  (:import [org.opensaml.saml.saml2.core LogoutResponse StatusCode]))

(defmulti validate-logout-response
  "Peform a validation operation on a LogoutResponse."
  (fn [validation _ _ _]
    (keyword validation)))

(defmethod validate-logout-response :default
  [& args]
  (apply response/validate-response args))

(defmethod validate-logout-response :success
  [_ _ ^LogoutResponse decrypted-response _]
  (let [status-value (.. decrypted-response getStatus getStatusCode getValue)]
    (when-not (= status-value StatusCode/SUCCESS)
      (throw (ex-info "LogoutResponse <Status> was not Success" {:status-value status-value})))))

(def default-logout-validation-options
  {:response-validators [:signature
                         :require-signature
                         :issuer
                         :success]})


(defn validate-logout
  "Decode a ring request into a LogoutResponse SAML object and validate it."
  ([req idp-cert]
   (validate-logout req idp-cert nil))
  ([req idp-cert options]
   (let [options (-> (merge default-logout-validation-options options)
                     (assoc :idp-cert (coerce/->Credential idp-cert)))
         {:keys [response-validators]} options]
     (when-let [response (coerce/->LogoutResponse req)]
       (doseq [validator response-validators]
         (validate-logout-response validator response response options))
       response))))
