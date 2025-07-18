(ns saml20-clj.crypto-test
  (:require
   [clojure.test :refer :all]
   [saml20-clj.crypto :as crypto]
   [saml20-clj.coerce :as coerce]
   [saml20-clj.test :as test]
   [saml20-clj.xml :as xml]
   [saml20-clj.opensaml-context :as opensaml-ctx])
  (:import
   [org.opensaml.messaging.context MessageContext]
   [org.opensaml.xmlsec.signature Signature]
   [java.security.cert X509Certificate]))

(deftest validate-signature-with-opensaml-test
  (testing "valid signature passes validation"
    (doseq [{:keys [response] :as response-map} (test/responses)]
      (when (test/has-valid-signature? response-map)
        (let [response-obj (coerce/->Response response)
              signature (.getSignature response-obj)]
          (when signature
            (is (= :valid
                   (crypto/validate-signature-with-opensaml
                    signature test/idp-cert))))))))

  (testing "invalid signature fails validation"
    (doseq [{:keys [response] :as response-map} (test/responses)]
      (when (and (test/signed? response-map)
                 (not (test/has-valid-signature? response-map)))
        (let [response-obj (coerce/->Response response)
              signature (.getSignature response-obj)]
          (when signature
            (is (thrown-with-msg?
                 clojure.lang.ExceptionInfo
                 #"Signature validation against credential failed"
                 (crypto/validate-signature-with-opensaml
                  signature test/idp-cert))))))))

  (testing "signature profile validation"
    (let [response-str (test/response {:message-signed? true})
          response-obj (coerce/->Response response-str)]
      (is (= :valid
             (crypto/validate-signature-with-opensaml
              response-obj test/idp-cert))))))

(deftest validate-certificate-chain-test
  (testing "valid certificate chain"
    (let [cert (coerce/->X509Certificate test/idp-cert)
          trust-anchors [cert]]
      (is (= :valid
             (crypto/validate-certificate-chain
              [cert] trust-anchors)))))

  (testing "invalid certificate chain throws CertPathValidatorException"
    (let [cert (coerce/->X509Certificate test/idp-cert)
          other-cert (coerce/->X509Certificate test/sp-cert)
          trust-anchors [other-cert]]
      (try
        (crypto/validate-certificate-chain [cert] trust-anchors)
        (is false "Should have thrown exception")
        (catch clojure.lang.ExceptionInfo e
          (is (re-find #"Certificate chain validation failed" (.getMessage e)))
          (is (= :certificate-chain-invalid (-> e ex-data :error-code))))))))

(deftest decrypt-with-validation-test
  (testing "successful decryption with encrypted assertion"
    (let [response-str (test/response {:assertion-encrypted? true})
          response-obj (coerce/->Response response-str)
          encrypted-assertions (.getEncryptedAssertions response-obj)]
      (when (seq encrypted-assertions)
        (let [encrypted-assertion (first encrypted-assertions)
              element (coerce/->Element encrypted-assertion)]
          (is (some? (crypto/decrypt-with-validation
                      element test/sp-private-key)))))))

  (testing "decryption with nil key returns nil"
    (let [response-str (test/response {:assertion-encrypted? true})
          response-obj (coerce/->Response response-str)
          encrypted-assertions (.getEncryptedAssertions response-obj)]
      (when (seq encrypted-assertions)
        (let [encrypted-assertion (first encrypted-assertions)
              element (coerce/->Element encrypted-assertion)]
          (is (nil? (crypto/decrypt-with-validation
                     element nil))))))))

(deftest validate-signature-with-context-test
  (testing "signature validation with trust engine"
    (let [response-str (test/response {:message-signed? true})
          response-obj (coerce/->Response response-str)
          signature (.getSignature response-obj)
          msg-ctx (MessageContext.)
          _ (opensaml-ctx/enhance-message-context msg-ctx {:idp-cert test/idp-cert})]
      (when signature
        (is (= :valid
               (crypto/validate-signature-with-context
                signature msg-ctx))))))

  (testing "signature validation without trust engine fails"
    (let [response-str (test/response {:message-signed? true})
          response-obj (coerce/->Response response-str)
          signature (.getSignature response-obj)
          msg-ctx (MessageContext.)]
      (when signature
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo
             #"No trust engine configured"
             (crypto/validate-signature-with-context
              signature msg-ctx)))))))

(deftest validate-encryption-method-test
  (testing "approved encryption algorithms"
    (let [algorithms ["http://www.w3.org/2001/04/xmlenc#aes128-cbc"
                      "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
                      "http://www.w3.org/2009/xmlenc11#aes256-gcm"]]
      (doseq [alg algorithms]
        (let [element (xml/str->xmldoc
                       (str "<EncryptedData Algorithm=\"" alg "\"/>"))]
          (is (= :valid
                 (crypto/validate-encryption-method element)))))))

  (testing "weak encryption algorithm fails"
    (let [element (xml/str->xmldoc
                   "<EncryptedData Algorithm=\"http://www.w3.org/2001/04/xmlenc#tripledes-cbc\"/>")]
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"Encryption algorithm does not meet security requirements"
           (crypto/validate-encryption-method element))))))

(deftest validate-signature-algorithm-test
  (testing "strong signature algorithms pass on real signatures"
    (let [response-str (test/response {:message-signed? true})
          response-obj (coerce/->Response response-str)
          signature (.getSignature response-obj)]
      (when (and signature
                 (not (#{"http://www.w3.org/2000/09/xmldsig#rsa-sha1"
                         "http://www.w3.org/2000/09/xmldsig#dsa-sha1"}
                       (.getSignatureAlgorithm signature))))
        (is (= :valid
               (crypto/validate-signature-algorithm signature)))))))

(deftest extract-certificate-chain-test
  (testing "extract certificates from signature"
    (let [response-str (test/response {:message-signed? true})
          response-obj (coerce/->Response response-str)
          signature (.getSignature response-obj)]
      (when (and signature (.getKeyInfo signature))
        (let [certs (crypto/extract-certificate-chain signature)]
          (is (vector? certs))
          (when (seq certs)
            (is (every? #(instance? X509Certificate %) certs))))))))

(deftest validate-key-info-test
  (testing "valid KeyInfo with certificate"
    (let [response-str (test/response {:message-signed? true})
          response-obj (coerce/->Response response-str)
          signature (.getSignature response-obj)]
      (when (and signature (.getKeyInfo signature))
        ;; Only test if there are actually certificates in the KeyInfo
        (let [key-info (.getKeyInfo signature)
              x509-datas (.getX509Datas key-info)
              has-certs? (some (fn [^org.opensaml.xmlsec.signature.X509Data x509-data]
                                 (seq (.getX509Certificates x509-data)))
                               x509-datas)]
          (when has-certs?
            (is (= :valid
                   (crypto/validate-key-info signature)))))))))
