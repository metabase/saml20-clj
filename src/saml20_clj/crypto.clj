(ns saml20-clj.crypto
  (:require [saml20-clj.coerce :as coerce])
  (:import org.apache.xml.security.Init
           org.opensaml.security.credential.Credential))

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
  (delay
    (Init/init)
    nil))

@-init

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
