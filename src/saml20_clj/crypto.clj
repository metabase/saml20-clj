(ns saml20-clj.crypto
  (:require [saml20-clj.coerce :as coerce])
  (:import org.apache.xml.security.Init
           org.opensaml.messaging.context.MessageContext
           org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler
           [org.opensaml.saml.common.messaging.context SAMLPeerEntityContext SAMLProtocolContext]
           org.opensaml.saml.common.xml.SAMLConstants
           org.opensaml.saml.saml2.binding.security.impl.SAML2HTTPRedirectDeflateSignatureSecurityHandler
           org.opensaml.saml.saml2.metadata.SPSSODescriptor
           [org.opensaml.security.credential BasicCredential Credential]
           org.opensaml.security.credential.impl.CollectionCredentialResolver
           org.opensaml.xmlsec.context.SecurityParametersContext
           org.opensaml.xmlsec.keyinfo.impl.BasicProviderKeyInfoCredentialResolver
           [org.opensaml.xmlsec.keyinfo.impl.provider DEREncodedKeyValueProvider DSAKeyValueProvider ECKeyValueProvider InlineX509DataProvider RSAKeyValueProvider]
           org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine
           org.opensaml.xmlsec.SignatureValidationParameters))

(set! *warn-on-reflection* true)

(defn has-private-key?
  "Will check if the provided keystore contains a private key or not."
  [credential]
  (when-let [^Credential credential (try
                                      (coerce/->Credential credential)
                                      (catch Throwable _
                                        (coerce/->Credential (coerce/->PrivateKey credential))))]
    (some? (.getPrivateKey credential))))

(defn decrypt! [sp-private-key element]
  (when-let [sp-private-key (coerce/->PrivateKey sp-private-key)]
    (when-let [element (coerce/->Element element)]
      (com.onelogin.saml2.util.Util/decryptElement element sp-private-key))))

(defn recursive-decrypt! [sp-private-key element]
  (when-let [sp-private-key (coerce/->PrivateKey sp-private-key)]
    (when-let [element (coerce/->Element element)]
      (when (and (= (.getLocalName element) "EncryptedAssertion")
                 (= (.getNamespaceURI element) "urn:oasis:names:tc:SAML:2.0:assertion"))
        (decrypt! sp-private-key element))
      (doseq [i     (range (.. element getChildNodes getLength))
              ;; Explict typehinting here required by Cloverage
              :let  [^org.w3c.dom.NodeList nodes (.getChildNodes element)
                     child (.item nodes i)]
              :when (instance? org.w3c.dom.Element child)]
        (recursive-decrypt! sp-private-key child)))))

(defonce ^:private -init
  (delay
    (Init/init)
    nil))

@-init

(defn authenticated?
  "True if the MessageContext's PeerEntity subcontext has isAuthenticated set"
  [^MessageContext msg-ctx]
  (let [^SAMLPeerEntityContext peer-entity-ctx (.. msg-ctx
                                                   (getSubcontext SAMLPeerEntityContext))]
    (.isAuthenticated peer-entity-ctx)))

(defn signature [object]
  (when-let [object (coerce/->SAMLObject object)]
    (.getSignature object)))

(defn assert-signature-valid-when-present
  [object credential]
  (when-let [signature (signature object)]
    (when-let [credential (coerce/->Credential credential)]
      ;; validate that the signature conforms to the SAML signature spec
      (try
        (.validate (org.opensaml.saml.security.impl.SAMLSignatureProfileValidator.) signature)
        (catch Throwable e
          (throw (ex-info "Signature does not conform to SAML signature spec"
                          {:object (coerce/->xml-string object)}
                          e))))
      ;; validate that the signature matches the credential
      (try
        (org.opensaml.xmlsec.signature.support.SignatureValidator/validate signature credential)
        (catch Throwable e
          (throw (ex-info "Signature does not match credential"
                          {:object (coerce/->xml-string object)}
                          e))))
      :valid)))

(def ^:private basic-key-info-cred-resolver
  (BasicProviderKeyInfoCredentialResolver. [(RSAKeyValueProvider.)
                                            (DSAKeyValueProvider.)
                                            (ECKeyValueProvider.)
                                            (DEREncodedKeyValueProvider.)
                                            (InlineX509DataProvider.)]))

(defn handle-signature-security
  "Uses OpenSAMLs security handlers to verify the signature of an incoming request for both
  GET and POST-based SAML flows.

  Returns the verified MessageContext for the request.

  The SAMLPeerEntityContext subcontext of the MessageContext will have a method isAuthenticated
  that returns true if the signature verification succeeded.

  It will raise if the verification fails and a signature was provided.

  It will return the message context if no sigature was provided but isAuthenticated will be
  false."
  ^MessageContext [^MessageContext msg-ctx request issuer credential]
  (let [credential (doto ^BasicCredential (coerce/->Credential credential)
                     (.setEntityId issuer))
        http-req-supplier (coerce/ring-request->HttpServletRequestSupplier request)
        sig-trust-engine (ExplicitKeySignatureTrustEngine.
                          (CollectionCredentialResolver. [credential])
                          basic-key-info-cred-resolver)
        sig-val-parameters (doto (SignatureValidationParameters.)
                             (.setSignatureTrustEngine sig-trust-engine))
        ^SAMLPeerEntityContext peer-entity-ctx (.ensureSubcontext msg-ctx SAMLPeerEntityContext)
        ^SAMLProtocolContext protocol-ctx (.ensureSubcontext msg-ctx SAMLProtocolContext)
        ^SecurityParametersContext sec-params-ctx (.ensureSubcontext msg-ctx SecurityParametersContext)]
    (doto peer-entity-ctx
      (.setEntityId issuer)
      (.setRole SPSSODescriptor/DEFAULT_ELEMENT_NAME))
    (.setProtocol protocol-ctx SAMLConstants/SAML20P_NS)
    (.setSignatureValidationParameters sec-params-ctx sig-val-parameters)

    ;; if we have a GET request we are dealing with a redirect where the signature is the query parameters
    ;; this uses a different security handler than POST requests where the signature is embedded in the
    ;; XML Document
    (if (= (:request-method request) :get)
      (doto (SAML2HTTPRedirectDeflateSignatureSecurityHandler.)
        (.setHttpServletRequestSupplier http-req-supplier)
        (.initialize)
        (.invoke msg-ctx))
      (doto (SAMLProtocolMessageXMLSignatureSecurityHandler.)
        (.initialize)
        (.invoke msg-ctx)))
    msg-ctx))
