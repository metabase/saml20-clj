(ns saml20-clj.sp.message
  "Common validators for all SAML messages"
  (:require [saml20-clj.crypto :as crypto])
  (:import [org.opensaml.messaging.context InOutOperationContext MessageContext]
           org.opensaml.messaging.handler.impl.CheckExpectedIssuer
           org.opensaml.saml.common.AbstractSAMLObjectBuilder
           org.opensaml.saml.common.binding.security.impl.InResponseToSecurityHandler
           [org.opensaml.saml.saml2.core RequestAbstractType StatusResponseType]))

(defn ->JavaFunction
  [func]
  (reify java.util.function.Function
    (apply [_ arg]
      (func arg))))

(defmulti validate-message
  "Peform a validation operation on a MessageCtx."
  (fn [validation _ _]
    (keyword validation)))

(defmethod validate-message :signature
  [_ ^MessageContext msg-ctx {:keys [request issuer idp-cert] :or {issuer "unknown"}}]
  (assert (seq request) "Must provide original request")
  (assert (not (nil? idp-cert)) "Must provide a credential for the idp")
  (try
    (crypto/handle-signature-security msg-ctx request issuer idp-cert)
    (catch org.opensaml.messaging.handler.MessageHandlerException e
      (throw (ex-info "Message failed to validate signature" {:validator :signature} e)))))

(defmethod validate-message :issuer
  [_ ^MessageContext msg-ctx {:keys [issuer]}]
  (assert (string? issuer) "Must provide issuer identifier for idp")
  (let [^StatusResponseType msg (.getMessage msg-ctx)
        incoming-issuer (when-let [issuer-element (.getIssuer msg)]
                          (.getValue issuer-element))]
    (try
      (doto (CheckExpectedIssuer.)
        (.setExpectedIssuerLookupStrategy (->JavaFunction (constantly issuer)))
        (.setIssuerLookupStrategy (->JavaFunction (constantly incoming-issuer)))
        (.initialize)
        (.invoke msg-ctx))
      (catch org.opensaml.messaging.handler.MessageHandlerException e
        (throw (ex-info "Message failed to validate issuer"
                        {:validator :issuer
                         :expected issuer
                         :actual incoming-issuer}
                        e))))))

;; TODO: Replace this with usage of opensaml's client storage system
(defmethod validate-message :in-response-to
  [_ ^MessageContext msg-ctx {:keys [request-id ^AbstractSAMLObjectBuilder request-builder]}]
  (assert (string? request-id) "Must provide the original request id")
  (assert (not (nil? request-builder)) "Must provide a request buidler")
  (let [^RequestAbstractType outgoing (.buildObject request-builder)]
    (.setID outgoing request-id)
    (InOutOperationContext. msg-ctx
                            (doto (MessageContext.)
                              (.setMessage outgoing))))
  (try
    (doto (InResponseToSecurityHandler.)
      (.initialize)
      (.invoke msg-ctx))
    (catch org.opensaml.messaging.handler.MessageHandlerException e
      (throw (ex-info "Message failed to validate InResponseTo"
                      {:validator :in-response-to
                       :original-request-id request-id
                       :incoming-request-id (.getInResponseTo ^StatusResponseType (.getMessage msg-ctx))}
                      e)))))

(defmethod validate-message :require-authenticated
  ;; Requires the response be signed either in the query params (HTTP-Redirect) in the
  ;; XML body (HTTP-Post), must run after signature validation
  [_ ^MessageContext msg-ctx _]
  (when-not (crypto/authenticated? msg-ctx)
    (throw (ex-info "Message is not Authenticated"
                    {:is-authenticated (crypto/authenticated? msg-ctx)
                     :validator :require-authenticated}))))
