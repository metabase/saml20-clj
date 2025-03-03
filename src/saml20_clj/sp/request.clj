 (ns saml20-clj.sp.request
   (:require [clojure.string :as str]
             [java-time.api :as t]
             [saml20-clj.coerce :as coerce]
             [saml20-clj.state :as state])
   (:import org.opensaml.messaging.context.MessageContext
            [org.opensaml.saml.common.messaging.context SAMLBindingContext SAMLEndpointContext SAMLPeerEntityContext]
            org.opensaml.saml.common.xml.SAMLConstants
            org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder
            [org.opensaml.saml.saml2.core AuthnRequest LogoutRequest NameIDType]
            [org.opensaml.saml.saml2.core.impl AuthnRequestBuilder IssuerBuilder LogoutRequestBuilder NameIDBuilder NameIDPolicyBuilder]
            org.opensaml.saml.saml2.metadata.impl.SingleSignOnServiceBuilder
            org.opensaml.xmlsec.context.SecurityParametersContext
            org.opensaml.xmlsec.SignatureSigningParameters))

(set! *warn-on-reflection* true)

(defn- non-blank-string? [s]
  (and (string? s)
       (not (str/blank? s))))

(defn- random-request-id
  "Generates a random ID for a SAML request, if none is provided."
  []
  (str "id" (random-uuid)))

(def ^:private -sig-alg "http://www.w3.org/2000/09/xmldsig#rsa-sha1")

(defn- setup-message-context
  [message credential sig-alg idp-url]
  (let [msgctx (doto (MessageContext.) (.setMessage message))]
    (when credential
      (let [decoded-credential (try
                                 (coerce/->Credential credential)
                                 (catch Throwable _
                                   (coerce/->Credential (coerce/->PrivateKey credential))))
            ^SecurityParametersContext security-context (.getSubcontext msgctx SecurityParametersContext true)]
        (.setSignatureSigningParameters security-context
                                        (doto (SignatureSigningParameters.)
                                          (.setSignatureAlgorithm sig-alg)
                                          (.setSigningCredential decoded-credential)))))

    (let [^SAMLPeerEntityContext peer-context (.getSubcontext msgctx SAMLPeerEntityContext true)
          ^SAMLEndpointContext endpoint-context (.getSubcontext peer-context SAMLEndpointContext true)]
      (.setEndpoint endpoint-context
                    (doto (.buildObject (SingleSignOnServiceBuilder.))
                      (.setBinding SAMLConstants/SAML2_REDIRECT_BINDING_URI)
                      (.setLocation idp-url))))
    msgctx))

(defn- build-authn-obj
  ^AuthnRequest [request-id instant sp-name idp-url acs-url issuer]
  (doto (.buildObject (AuthnRequestBuilder.))
    (.setID request-id)
    (.setIssueInstant instant)
    (.setDestination idp-url)
    (.setProtocolBinding SAMLConstants/SAML2_REDIRECT_BINDING_URI)
    (.setIsPassive false)
    (.setProviderName sp-name)
    (.setAssertionConsumerServiceURL acs-url)
    (.setNameIDPolicy (doto (.buildObject (NameIDPolicyBuilder.))
                        (.setFormat NameIDType/UNSPECIFIED)))
    (.setIssuer (doto (.buildObject (IssuerBuilder.))
                  (.setValue issuer)))))

(defn- authn-request
  "Return an OpenSAML MessageContext Object with a SAML AuthnRequest."
  ^MessageContext [request-id
                   sp-name
                   acs-url
                   idp-url
                   issuer
                   state-manager
                   credential
                   sig-alg
                   instant]
  (let [request (build-authn-obj request-id instant sp-name idp-url acs-url issuer)]
    (when state-manager
      (state/record-request! state-manager (.getID request)))
    (setup-message-context request credential sig-alg idp-url)))

(defn- map-making-servlet
  "Implements a minimum HttpServletResponse for HTTPRedirectDeflateEncoder"
  []
  (let [response (
atom {:status 302 :body "" :headers {}})
        servlet-wrapper (reify jakarta.servlet.http.HttpServletResponse
                          (setHeader [_this name value]
                            (swap! response update :headers assoc name value))
                          (^void setCharacterEncoding [_ ^String _])
                          (sendRedirect [this redirect]
                            (.setHeader this "location" redirect)))
        wrapper-supplier (reify net.shibboleth.shared.primitive.NonnullSupplier
                           (get [_] servlet-wrapper))]
    [wrapper-supplier #(deref response)]))

(defn- redirect-response
  [^MessageContext saml-request relay-state]
  (let [[servlet ->ring-request] (map-making-servlet)
        ^SAMLBindingContext binding-context (.getSubcontext saml-request SAMLBindingContext true)]
    ;; set the relay state
    (.setRelayState binding-context relay-state)

    ;; Hand over to an opensaml encoder with a servletresponse implementation that allows us to
    ;; retrieve the result as a ring map
    (doto (HTTPRedirectDeflateEncoder.)
      (.setMessageContext saml-request)
      (.setHttpServletResponseSupplier servlet)
      (.initialize)
      (.encode))
    (->ring-request)))

(defn- build-logout-obj
  ^LogoutRequest [issuer user-email idp-url instant request-id]
  (assert (non-blank-string? idp-url) "idp-url is required")
  (assert (non-blank-string? issuer) "issuer is required")
  (assert (non-blank-string? user-email) "user-email is required")
  (doto (.buildObject (LogoutRequestBuilder.))
    (.setID request-id)
    (.setIssueInstant instant)
    (.setDestination idp-url)
    (.setIssuer (doto (.buildObject (IssuerBuilder.))
                  (.setValue issuer)))
    (.setNameID (doto (.buildObject (NameIDBuilder.))
                  (.setValue user-email)))))

(defn idp-redirect-response
  "Return Ring response for HTTP 302 redirect."
  [{:keys [ ;; e.g. something like a UUID. Random UUID will be used if no other ID is provided
           request-id
           ;; e.g. "Metabase"
           sp-name
           ;; e.g. http://sp.example.com/demo1/index.php?acs
           acs-url
           ;; e.g. http://idp.example.com/SSOService.php
           idp-url
           ;; e.g. http://sp.example.com/demo1/metadata.php
           issuer
           ;; If present, record the request
           state-manager
           ;; If present, we can sign the request
           credential
           ;; Signature Algorithm
           sig-alg
           ;; relay-state argument that will be returned by the provider
           relay-state
           instant]
    :or   {instant (t/instant)
           request-id (random-request-id)
           sig-alg -sig-alg}}]
  (assert (non-blank-string? acs-url) "acs-url is required")
  (assert (non-blank-string? idp-url) "idp-url is required")
  (assert (non-blank-string? sp-name) "sp-name is required")
  (assert (non-blank-string? issuer) "issuer is required")
  (redirect-response (authn-request request-id
                                    sp-name
                                    acs-url
                                    idp-url
                                    issuer
                                    state-manager
                                    credential
                                    sig-alg
                                    instant)
                     relay-state))

(defn idp-logout-redirect-response
  "Return Ring response for HTTP 302 redirect."
  ([issuer user-email idp-url relay-state]
   (idp-logout-redirect-response issuer user-email idp-url relay-state (random-request-id)))
  ([issuer user-email idp-url relay-state request-id]
   (idp-logout-redirect-response {:issuer issuer
                                  :user-email user-email
                                  :idp-url idp-url
                                  :relay-state relay-state
                                  :request-id request-id}))
  ([{:keys [request-id instant idp-url issuer user-email credential relay-state sig-alg]
     :or {instant (t/instant)
          request-id (random-request-id)
          sig-alg -sig-alg}}]
   (let [logout-request (build-logout-obj issuer user-email idp-url instant request-id)]
     (redirect-response (setup-message-context logout-request credential sig-alg idp-url) relay-state))))

(defn logout-redirect-location
  [& args]
  (get-in (idp-logout-redirect-response args) [:headers "location"]))
