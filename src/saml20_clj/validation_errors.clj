(ns saml20-clj.validation-errors
  "Structured error handling for SAML validation failures"
  (:require [saml20-clj.coerce :as coerce]))

(def validation-errors
  "Enumeration of all possible error types for SAML validation."
  {:signature-validation
   {:code :invalid-signature
    :message "SAML signature validation failed"
    :severity :high}
   :timing-validation
   {:code :invalid-timing
    :message "SAML timing conditions not met"
    :severity :medium}
   :issuer-validation
   {:code :invalid-issuer
    :message "SAML issuer validation failed"
    :severity :high}
   :recipient-validation
   {:code :invalid-recipient
    :message "SAML recipient validation failed"
    :severity :high}
   :encryption-required
   {:code :encryption-required
    :message "Unencrypted assertions present in response body"
    :severity :high}
   :in-response-to-validation
   {:code :invalid-in-response-to
    :message "SAML InResponseTo validation failed"
    :severity :medium}
   :subject-confirmation-validation
   {:code :invalid-subject-confirmation
    :message "SAML SubjectConfirmation validation failed"
    :severity :high}
   :assertion-replayed
   {:code :assertion-replayed
    :message "SAML assertion has been replayed"
    :severity :high}
   :audience-restriction
   {:code :invalid-audience
    :message "SAML audience restriction validation failed"
    :severity :high}
   :authn-statement
   {:code :invalid-authn-statement
    :message "SAML authentication statement validation failed"
    :severity :medium}
   :conditions-validation
   {:code :invalid-conditions
    :message "SAML conditions validation failed"
    :severity :high}
   :one-time-use
   {:code :one-time-use-violation
    :message "SAML OneTimeUse condition violated"
    :severity :high}
   :proxy-restriction
   {:code :proxy-restriction-violation
    :message "SAML ProxyRestriction condition violated"
    :severity :medium}
   :status-code
   {:code :invalid-status-code
    :message "SAML response contains non-success status"
    :severity :high}
   :assertion-count
   {:code :invalid-assertion-count
    :message "SAML response contains unexpected number of assertions"
    :severity :medium}
   :logout-failed
   {:code :logout-failed
    :message "SAML logout response indicates failure"
    :severity :high}
   :logout-correlation-failed
   {:code :logout-correlation-failed
    :message "SAML logout response does not correlate with request"
    :severity :high}
   :decryption-failed
   {:code :decryption-failed
    :message "Failed to decrypt SAML assertion"
    :severity :high}
   :missing-required-element
   {:code :missing-required-element
    :message "Required SAML element is missing"
    :severity :high}
   :authentication-required
   {:code :authentication-required
    :message "SAML message is not authenticated"
    :severity :high}
   :missing-attribute-statement
   {:code :missing-attribute-statement
    :message "SAML assertion missing required AttributeStatement"
    :severity :medium}
   :authorization-denied
   {:code :authorization-denied
    :message "SAML authorization decision statement denied access"
    :severity :high}
   :invalid-authn-context
   {:code :invalid-authn-context
    :message "SAML authentication context does not meet requirements"
    :severity :high}
   :replay-prevention
   {:code :replay-prevention
    :message "SAML assertion has been processed before (replay attack detected)"
    :severity :high}})

(defn validation-error
  "Create a structured validation error with rich context"
  ([type element context]
   (validation-error type element context nil))
  ([type element context cause]
   (let [error-def (get validation-errors type)]
     (ex-info (:message error-def)
              (merge context
                     {:error-type type
                      :error-code (:code error-def)
                      :severity (:severity error-def)
                      :saml-element (when element
                                      (try
                                        (coerce/->xml-string element)
                                        (catch Exception _
                                          (str element))))
                      :validation-context context})
              cause))))

(defn get-error-severity
  "Get the severity level of a validation error type"
  [error-type]
  (get-in validation-errors [error-type :severity]))

(defn is-critical-error?
  "Check if an error type is considered critical (high severity)"
  [error-type]
  (= :high (get-error-severity error-type)))
