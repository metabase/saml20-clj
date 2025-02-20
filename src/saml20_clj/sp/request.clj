(ns saml20-clj.sp.request
  (:require [clojure.string :as str]
            [java-time.api :as t]
            [ring.util.codec :as codec]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.encode-decode :as encode-decode]
            [saml20-clj.state :as state])
  (:import org.opensaml.messaging.context.MessageContext
           [org.opensaml.saml.common.messaging.context SAMLBindingContext SAMLEndpointContext SAMLPeerEntityContext]
           org.opensaml.saml.common.xml.SAMLConstants
           org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder
           [org.opensaml.saml.saml2.core AuthnRequest NameIDType]
           [org.opensaml.saml.saml2.core.impl AuthnRequestBuilder IssuerBuilder NameIDPolicyBuilder]
           org.opensaml.saml.saml2.metadata.impl.SingleSignOnServiceBuilder
           org.opensaml.xmlsec.context.SecurityParametersContext
           org.opensaml.xmlsec.SignatureSigningParameters))

(defn- format-instant
  "Converts a date-time to a SAML 2.0 time string."
  [instant]
  (t/format (t/format "YYYY-MM-dd'T'HH:mm:ss'Z'" (t/offset-date-time instant (t/zone-offset 0)))))

(defn- non-blank-string? [s]
  (and (string? s)
       (not (str/blank? s))))

(defn random-request-id
  "Generates a random ID for a SAML request, if none is provided."
  []
  (str "id" (random-uuid)))

(def ^:private -sig-alg "http://www.w3.org/2000/09/xmldsig#rsa-sha1")

(defn build-authn-obj
  ^AuthnRequest [request-id instant sp-name idp-url acs-url issuer]
  (doto (.buildObject (AuthnRequestBuilder.)
    ;; these override the xml qname used by opensaml so our generate messages don't
    ;; change. As far I can tell from the spec, is it fine for these qnames to either
    ;; be samlp/saml like our previous xml generation or to be saml2p/saml2 which
    ;; opensaml deafults to
                      SAMLConstants/SAML20P_NS
                      "AuthnRequest"
                      "samlp")
    (.setID request-id)
    (.setIssueInstant instant)
    (.setDestination idp-url)
    (.setProtocolBinding SAMLConstants/SAML2_REDIRECT_BINDING_URI)
    (.setIsPassive false)
    (.setProviderName sp-name)
    (.setAssertionConsumerServiceURL acs-url)
    (.setNameIDPolicy (doto (.buildObject (NameIDPolicyBuilder.)
                                          SAMLConstants/SAML20P_NS
                                          "NameIDPolicy"
                                          "samlp")
                        (.setFormat NameIDType/UNSPECIFIED)))
    (.setIssuer (doto (.buildObject (IssuerBuilder.)
                                    SAMLConstants/SAML20_NS
                                    "Issuer"
                                    "saml")
                  (.setValue issuer)))))

(defn request
  "Return an OpenSAML MessageContext Object with a SAML AuthnRequest."
  ^MessageContext [{:keys [;; e.g. something like a UUID. Random UUID will be used if no other ID is provided
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
                           instant]
                    :or   {instant (t/instant)
                           request-id (random-request-id)
                           sig-alg -sig-alg}}]
  (assert (non-blank-string? acs-url) "acs-url is required")
  (assert (non-blank-string? idp-url) "idp-url is required")
  (assert (non-blank-string? sp-name) "sp-name is required")
  (assert (non-blank-string? issuer) "issuer is required")
  (let [request (build-authn-obj request-id instant sp-name idp-url acs-url issuer)
        msgctx (doto (MessageContext.) (.setMessage request))]
    (when state-manager
      (state/record-request! state-manager (.getID request)))
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

(defn- add-query-params
  "Add query parameters to a URL.

  (add-query-params \"http://example.com\" {:a \"b\" :c \"d\"}
  ;; => \"http://example.com?a=b&c=d\""
  [url params]
  (str url (if (str/includes? url "?") "&" "?") (codec/form-encode params)))

(defn- map-making-servlet
  "Implements a minimum HttpServletResponse for HTTPRedirectDeflateEncoder"
  []
  (let [response (atom {:status 302 :body "" :headers {}})
        servlet-wrapper (reify jakarta.servlet.http.HttpServletResponse
                          (setHeader [_this name value]
                            (swap! response update :headers assoc name value))
                          (^void setCharacterEncoding [_ ^String _])
                          (sendRedirect [this redirect]
                            (.setHeader this "location" redirect)))
        wrapper-supplier (reify net.shibboleth.shared.primitive.NonnullSupplier
                           (get [_] servlet-wrapper))]
    [wrapper-supplier #(deref response)]))

(defn idp-redirect-response
  "Return Ring response for HTTP 302 redirect."
  [^MessageContext saml-request relay-state]
  {:pre [(some? saml-request)
         (string? relay-state)]}

  ;; implmenets HttpServletResponse interface and provides a function for retrieving the request
  ;; as a ring map
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

;; I wanted to call this make-request-xml, but it gets exported in core.clj, which
;; warrants the request prefix
(defn make-logout-request-xml
  "Generates a SAML 2.0 logout request, as a hiccupey datastructure."
  [& {:keys [request-id instant idp-url issuer user-email]
      :or {instant (format-instant (t/instant))}}]
  (assert (non-blank-string? idp-url) "idp-url is required")
  (assert (non-blank-string? issuer) "issuer is required")
  (assert (non-blank-string? user-email) "user-email is required")
  [:samlp:LogoutRequest {:xmlns "urn:oasis:names:tc:SAML:2.0:protocol"
                         :xmlns:samlp "urn:oasis:names:tc:SAML:2.0:protocol"
                         :xmlns:saml "urn:oasis:names:tc:SAML:2.0:assertion"
                         :Version "2.0"
                         :ID (or request-id (str "id" (random-uuid)))
                         :IssueInstant instant
                         :Destination idp-url}
   [:Issuer {:xmlns "urn:oasis:names:tc:SAML:2.0:assertion"} issuer]
   [:NameID {:xmlns "urn:oasis:names:tc:SAML:2.0:assertion"
             :Format "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"} user-email]])

(defn logout-redirect-location
  "This returns a url that you'd want to redirect a client to. Either using
  `ring/redirect` with a 302 status code or passing it to a client in a post body
  to have them redirect to."
  [& {:keys [issuer user-email idp-url relay-state request-id]}]
  (assert (non-blank-string? idp-url) "idp-url is required")
  (assert (non-blank-string? user-email) "user-email is required")
  (assert (non-blank-string? issuer) "issuer is required")
  (assert (non-blank-string? relay-state) "relay-state is required")
  (add-query-params idp-url {:SAMLRequest (encode-decode/str->deflate->base64
                                           (coerce/->xml-string (make-logout-request-xml
                                                                 :idp-url idp-url
                                                                 :request-id request-id
                                                                 :issuer issuer
                                                                 :user-email user-email)))
                             :RelayState relay-state}))

(defn idp-logout-redirect-response
  "Return Ring response for HTTP 302 redirect."
  ([issuer user-email idp-url relay-state]
   (idp-logout-redirect-response issuer user-email idp-url relay-state (random-request-id)))
  ([issuer user-email idp-url relay-state request-id]
   (let [url (logout-redirect-location
              :idp-url idp-url
              :user-email user-email
              :issuer issuer
              :relay-state relay-state
              :request-id request-id)]
     {:status  302 ; found
      :headers {"Location" url}
      :body    ""})))
