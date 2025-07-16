(ns saml20-clj.opensaml-context
  "OpenSAML security context integration for enhanced validation"
  (:require
   [saml20-clj.coerce :as coerce])
  (:import
   [org.opensaml.messaging.context MessageContext]
   [org.opensaml.saml.common.messaging.context SAMLPeerEntityContext]
   [org.opensaml.security.credential.impl CollectionCredentialResolver]
   [org.opensaml.xmlsec SignatureValidationParameters]
   [org.opensaml.xmlsec.context SecurityParametersContext]
   [org.opensaml.xmlsec.config.impl DefaultSecurityConfigurationBootstrap]
   [org.opensaml.xmlsec.signature.support.impl ExplicitKeySignatureTrustEngine]))

(set! *warn-on-reflection* true)

(defn create-credential-resolver
  "Create a credential resolver from certificates"
  [certificates]
  (let [credentials (map coerce/->Credential certificates)]
    (CollectionCredentialResolver. credentials)))

(defn create-trust-engine
  "Create a signature trust engine for validation"
  [idp-cert]
  (let [credential (coerce/->Credential idp-cert)
        resolver (CollectionCredentialResolver. [credential])
        key-info-resolver (DefaultSecurityConfigurationBootstrap/buildBasicInlineKeyInfoCredentialResolver)]
    (ExplicitKeySignatureTrustEngine. resolver key-info-resolver)))

(defn create-signature-validation-params
  "Create signature validation parameters with trust engine"
  [idp-cert]
  (doto (SignatureValidationParameters.)
    (.setSignatureTrustEngine (create-trust-engine idp-cert))))

;; Note: Decryption parameters are not available in OpenSAML 5
;; This is a placeholder for future enhancement 

(defn create-security-parameters-context
  "Create a security parameters context with validation configuration"
  [{:keys [idp-cert]}]
  (let [context (SecurityParametersContext.)
        sig-params (create-signature-validation-params idp-cert)]
    (.setSignatureValidationParameters context sig-params)
    context))

(defn enhance-message-context
  "Enhance a MessageContext with security parameters"
  [^MessageContext msg-ctx options]
  (when-not (.getSubcontext msg-ctx SecurityParametersContext)
    (let [security-ctx (create-security-parameters-context options)]
      (.addSubcontext msg-ctx security-ctx)))
  msg-ctx)

(defn get-peer-entity-context
  "Get or create a peer entity context"
  [^MessageContext msg-ctx]
  (or (.getSubcontext msg-ctx SAMLPeerEntityContext)
      (let [peer-ctx (SAMLPeerEntityContext.)]
        (.addSubcontext msg-ctx peer-ctx)
        peer-ctx)))

(defn set-peer-entity-id
  "Set the peer entity ID (IdP issuer) in the message context"
  [^MessageContext msg-ctx entity-id]
  (when entity-id
    (let [^SAMLPeerEntityContext peer-ctx (get-peer-entity-context msg-ctx)]
      (.setEntityId peer-ctx entity-id))))

(defn get-security-parameters
  "Get security parameters from message context"
  [^MessageContext msg-ctx]
  (.getSubcontext msg-ctx SecurityParametersContext))

(defn get-signature-trust-engine
  "Get the signature trust engine from security parameters"
  [^MessageContext msg-ctx]
  (when-let [^SecurityParametersContext sec-params (get-security-parameters msg-ctx)]
    (when-let [^SignatureValidationParameters sig-params (.getSignatureValidationParameters sec-params)]
      (.getSignatureTrustEngine sig-params))))
