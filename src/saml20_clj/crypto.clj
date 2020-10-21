(ns saml20-clj.crypto
  (:require [saml20-clj.coerce :as coerce])
  (:import org.apache.xml.security.Init
           org.opensaml.security.credential.Credential
           org.opensaml.xmlsec.signature.support.SignatureConstants))

(def signature-algorithms
  {:dsa   {nil     SignatureConstants/ALGO_ID_SIGNATURE_DSA
           :sha1   SignatureConstants/ALGO_ID_SIGNATURE_DSA_SHA1
           :sha256 SignatureConstants/ALGO_ID_SIGNATURE_DSA_SHA256}
   :rsa   {nil        SignatureConstants/ALGO_ID_SIGNATURE_RSA
           :sha1      SignatureConstants/ALGO_ID_SIGNATURE_RSA_SHA1
           :ripemd160 SignatureConstants/ALGO_ID_SIGNATURE_RSA_RIPEMD160
           :sha256    SignatureConstants/ALGO_ID_SIGNATURE_RSA_SHA256
           :sha224    SignatureConstants/ALGO_ID_SIGNATURE_RSA_SHA224
           :sha384    SignatureConstants/ALGO_ID_SIGNATURE_RSA_SHA384
           :sha512    SignatureConstants/ALGO_ID_SIGNATURE_RSA_SHA512}
   :ecdsa {:sha1   SignatureConstants/ALGO_ID_SIGNATURE_ECDSA_SHA1
           :sha224 SignatureConstants/ALGO_ID_SIGNATURE_ECDSA_SHA224
           :sha256 SignatureConstants/ALGO_ID_SIGNATURE_ECDSA_SHA256
           :sha384 SignatureConstants/ALGO_ID_SIGNATURE_ECDSA_SHA384
           :sha512 SignatureConstants/ALGO_ID_SIGNATURE_ECDSA_SHA512}})

(def canonicalization-algorithms
  {:omit-comments      SignatureConstants/ALGO_ID_C14N_OMIT_COMMENTS
   :with-comments      SignatureConstants/ALGO_ID_C14N_WITH_COMMENTS
   :excl-omit-comments SignatureConstants/ALGO_ID_C14N_EXCL_OMIT_COMMENTS
   :excl-with-comments SignatureConstants/ALGO_ID_C14N_EXCL_WITH_COMMENTS})

;; TODO -- I'm pretty sure this mutates `object`
(defn sign
  ^org.w3c.dom.Element [object credential & {:keys [signature-algorithm
                                                    canonicalization-algorithm]
                                             :or   {signature-algorithm        [:rsa :sha256]
                                                    canonicalization-algorithm :excl-omit-comments}}]
  (when-let [object (coerce/->SAMLObject object)]
    (when-let [^Credential credential (try
                                        (coerce/->Credential credential)
                                        (catch Throwable _
                                          (coerce/->Credential (coerce/->PrivateKey credential))))]
      (let [signature (doto (.buildObject (org.opensaml.xmlsec.signature.impl.SignatureBuilder.))
                        (.setSigningCredential credential)
                        (.setSignatureAlgorithm (or (get-in signature-algorithms signature-algorithm)
                                                    (throw (ex-info "No matching signature algorithm"
                                                                    {:algorithm signature-algorithm}))))
                        (.setCanonicalizationAlgorithm (or (get canonicalization-algorithms canonicalization-algorithm)
                                                           (throw (ex-info "No matching canonicalization algorithm"
                                                                           {:algorithm canonicalization-algorithm})))))
            key-info-gen (doto (new org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory)
                           (.setEmitEntityCertificate true))]
        (when-let [key-info (.generate (.newInstance key-info-gen) credential)] ; No need to test X509 coercion first
          (.setKeyInfo signature key-info))
        (.setSignature object signature)
        (let [element (coerce/->Element object)]
          (org.opensaml.xmlsec.signature.support.Signer/signObject signature)
          element)))))

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
              :let  [child (.. element getChildNodes (item i))]
              :when (instance? org.w3c.dom.Element child)]
        (recursive-decrypt! sp-private-key child)))))

(defn ^:private secure-random-bytes
  (^bytes [size]
   (let [ba (byte-array size)
         r  (java.security.SecureRandom.)]
     (.nextBytes r ba)
     ba))
  (^bytes []
   (secure-random-bytes 20)))

(defn new-secret-key ^javax.crypto.spec.SecretKeySpec []
  (javax.crypto.spec.SecretKeySpec. (secure-random-bytes) "HmacSHA1"))

(defonce ^:private -init
  (do
    (Init/init)
    nil))

(defn signed? [object]
  (when-let [object (coerce/->SAMLObject object)]
    (.isSigned object)))

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
