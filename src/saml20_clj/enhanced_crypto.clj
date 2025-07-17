(ns saml20-clj.enhanced-crypto
  "Enhanced cryptographic validation using OpenSAML 5 features"
  (:require
   [saml20-clj.coerce :as coerce]
   [saml20-clj.validation-errors :as errors]
   [saml20-clj.opensaml-context :as opensaml-ctx]
   [clojure.tools.logging :as log])
  (:import
   [java.security.cert CertPathValidator CertificateException PKIXParameters TrustAnchor X509Certificate]
   [org.opensaml.xmlsec.signature Signature]
   [org.opensaml.xmlsec.signature.support SignatureValidator]
   [org.opensaml.saml.security.impl SAMLSignatureProfileValidator]
   [org.opensaml.messaging.context MessageContext]
   [org.opensaml.xmlsec.encryption.support DecryptionException]
   [org.opensaml.xmlsec.signature.support SignatureException]
   [net.shibboleth.shared.resolver CriteriaSet]
   [org.opensaml.xmlsec.signature.support SignatureValidationParametersCriterion]))

(set! *warn-on-reflection* true)

(defn validate-signature-with-opensaml
  "Enhanced signature validation using OpenSAML's trust engine"
  [element credential]
  (let [^Signature signature (if (instance? Signature element)
                               element
                               (when-let [obj (coerce/->SAMLObject element)]
                                 (.getSignature obj)))]
    (when signature
      ;; First validate SAML signature profile compliance
      (try
        (.validate (SAMLSignatureProfileValidator.) signature)
        (catch SignatureException e
          (throw (errors/validation-error
                  :signature-profile-invalid
                  element
                  {:error-message (.getMessage e)}
                  e))))

      ;; Then validate signature with credential
      (try
        (SignatureValidator/validate signature (coerce/->Credential credential))
        :valid
        (catch SignatureException e
          (throw (errors/validation-error
                  :signature-validation-failed
                  element
                  {:credential-entity-id (when-let [cred (coerce/->Credential credential)]
                                           (.getEntityId cred))}
                  e)))))))

(defn validate-certificate-chain
  "Validate a certificate chain against trust anchors"
  [cert-chain trust-anchors]
  (try
    (let [trust-anchor-set (java.util.HashSet.)
          _ (doseq [anchor trust-anchors]
              (.add trust-anchor-set (TrustAnchor. ^X509Certificate anchor nil)))
          params (doto (PKIXParameters. trust-anchor-set)
                   (.setRevocationEnabled false)) ; Can be enabled if CRL/OCSP is configured
          validator (CertPathValidator/getInstance "PKIX")
          cert-factory (java.security.cert.CertificateFactory/getInstance "X.509")
          cert-path (.generateCertPath cert-factory ^java.util.List cert-chain)]
      (.validate validator cert-path params)
      :valid)
    (catch CertificateException e
      (throw (errors/validation-error
              :certificate-chain-invalid
              nil
              {:chain-length (count cert-chain)
               :trust-anchors (count trust-anchors)
               :error-message (.getMessage e)}
              e)))))

(defn enable-revocation-checking
  "Enable certificate revocation checking for PKIXParameters"
  [^PKIXParameters params]
  (doto params
    (.setRevocationEnabled true)))

(defn decrypt-with-validation
  "Enhanced decryption with better error handling and validation"
  [encrypted-element private-key]
  (try
    (when-let [private-key (coerce/->PrivateKey private-key)]
      (when-let [element (coerce/->Element encrypted-element)]
        ;; Log decryption attempt for debugging
        (log/debug "Attempting to decrypt element"
                   {:element-name (.getLocalName element)
                    :element-ns (.getNamespaceURI element)})

        (let [result (com.onelogin.saml2.util.Util/decryptElement element private-key)]
          (log/debug "Decryption successful")
          result)))
    (catch DecryptionException e
      (throw (errors/validation-error
              :decryption-failed
              encrypted-element
              {:private-key-present (some? private-key)
               :element-type (when encrypted-element
                               (.getLocalName (coerce/->Element encrypted-element)))
               :error-message (.getMessage e)}
              e)))
    (catch Exception e
      (throw (errors/validation-error
              :decryption-error
              encrypted-element
              {:private-key-present (some? private-key)
               :error-type (type e)
               :error-message (.getMessage e)}
              e)))))

(defn validate-signature-with-context
  "Validate signature using MessageContext with trust engine"
  [^Signature signature ^MessageContext msg-ctx]
  (if-let [^org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine trust-engine (opensaml-ctx/get-signature-trust-engine msg-ctx)]
    (let [criteria-set (CriteriaSet.)]
      (.add criteria-set (SignatureValidationParametersCriterion.
                          (opensaml-ctx/get-signature-validation-params msg-ctx)))
      (try
        (when-not (.validate trust-engine signature criteria-set)
          (throw (errors/validation-error
                  :signature-trust-validation-failed
                  signature
                  {:trust-engine-type (type trust-engine)})))
        :valid
        (catch Exception e
          (throw (errors/validation-error
                  :signature-trust-validation-error
                  signature
                  {:error-type (type e)
                   :error-message (.getMessage e)}
                  e)))))
    (throw (errors/validation-error
            :no-trust-engine-configured
            signature
            {}))))

(defn validate-key-info
  "Validate KeyInfo element in signatures"
  [signature]
  (when-let [^Signature sig (coerce/->Signature signature)]
    (when-let [key-info (.getKeyInfo sig)]
      ;; Validate that KeyInfo contains expected content
      (let [x509-datas (.getX509Datas key-info)
            has-cert? (some (fn [^org.opensaml.xmlsec.signature.X509Data x509-data]
                              (not (.isEmpty (.getX509Certificates x509-data))))
                            x509-datas)]
        (when-not has-cert?
          (throw (errors/validation-error
                  :key-info-missing-certificate
                  signature
                  {:key-info-present true
                   :x509-data-count (count x509-datas)})))
        :valid))))

(defn extract-certificate-chain
  "Extract certificate chain from a signature's KeyInfo"
  [signature]
  (when-let [^Signature sig (coerce/->Signature signature)]
    (when-let [key-info (.getKeyInfo sig)]
      (let [certs (for [^org.opensaml.xmlsec.signature.X509Data x509-data (.getX509Datas key-info)
                        ^org.opensaml.xmlsec.signature.X509Certificate x509-cert (.getX509Certificates x509-data)]
                    (coerce/->X509Certificate (.getValue x509-cert)))]
        (vec certs)))
    []))

(defn validate-encryption-method
  "Validate that encryption methods meet security requirements"
  [encrypted-element]
  (when-let [element (coerce/->Element encrypted-element)]
    (let [algorithm (when (= (.getLocalName element) "EncryptedData")
                      (.getAttribute element "Algorithm"))
          ;; List of approved algorithms
          approved-algorithms #{"http://www.w3.org/2001/04/xmlenc#aes128-cbc"
                                "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
                                "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
                                "http://www.w3.org/2009/xmlenc11#aes128-gcm"
                                "http://www.w3.org/2009/xmlenc11#aes192-gcm"
                                "http://www.w3.org/2009/xmlenc11#aes256-gcm"}]
      (when algorithm
        (when-not (approved-algorithms algorithm)
          (throw (errors/validation-error
                  :weak-encryption-algorithm
                  element
                  {:algorithm algorithm
                   :approved-algorithms approved-algorithms}))))
      :valid)))

(defn validate-signature-algorithm
  "Validate that signature algorithms meet security requirements"
  [signature]
  (when-let [^Signature sig (coerce/->Signature signature)]
    (let [algorithm (.getSignatureAlgorithm sig)
          ;; Disallow weak algorithms
          weak-algorithms #{"http://www.w3.org/2000/09/xmldsig#rsa-sha1"
                            "http://www.w3.org/2000/09/xmldsig#dsa-sha1"}]
      (when (weak-algorithms algorithm)
        (throw (errors/validation-error
                :weak-signature-algorithm
                signature
                {:algorithm algorithm
                 :recommendation "Use SHA-256 or stronger"})))
      :valid)))
