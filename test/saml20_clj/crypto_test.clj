(ns saml20-clj.crypto-test
  (:require [clojure.test :refer :all]
            [java-time.api :as t]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.crypto :as crypto]
            [saml20-clj.sp.request :as request]
            [saml20-clj.test :as test]))

(deftest sign-request-test
  (testing "Signature should be valid when signing request"
    (let [signed (t/with-clock (t/mock-clock (t/instant "2020-09-24T22:51:00.000Z"))
                   (request/request
                    {:request-id  "ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24"
                     :sp-name     "SP test"
                     :acs-url     "http://sp.example.com/demo1/index.php?acs"
                     :idp-url     "http://idp.example.com/SSOService.php"
                     :issuer      "http://sp.example.com/demo1/metadata.php"
                     :credential  test/sp-private-key}))]
      (is (= :valid
             (crypto/assert-signature-valid-when-present signed test/sp-cert)))
      (testing "Wrong certificate"
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo
             #"Signature does not match credential"
             (crypto/assert-signature-valid-when-present signed test/idp-cert)))))))

(deftest assert-signature-invalid-swapped-signature
  (doseq [{:keys [response], :as response-map} (test/responses)
          :when (test/malicious-signature? response-map)]
    (testing (test/describe-response-map response-map)
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"Signature does not match credential"
           (crypto/assert-signature-valid-when-present response test/idp-cert))))))

(deftest signature-validity-over-message-test
  (testing "Signatures different for different messages"
    (let [signed                     (t/with-clock (t/mock-clock (t/instant "2020-09-24T22:51:00.000Z"))
                                       (request/request
                                        {:request-id "ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24"
                                         :sp-name    "SP test"
                                         :acs-url    "http://sp.example.com/demo1/index.php?acs"
                                         :idp-url    "http://idp.example.com/SSOService.php"
                                         :issuer     "http://sp.example.com/demo1/metadata.php"
                                         :credential test/sp-private-key}))
          signed-signature           (crypto/signature signed)
          signed-duplicate           (t/with-clock (t/mock-clock (t/instant "2020-09-24T22:51:00.000Z"))
                                       (request/request
                                        {:request-id "COMPLETELY_DIFFERENT_REQUEST_ID"
                                         :sp-name    "SP test"
                                         :acs-url    "http://sp.example.com/demo1/index.php?acs"
                                         :idp-url    "http://idp.example.com/SSOService.php"
                                         :issuer     "http://sp.example.com/demo1/metadata.php"
                                         :credential test/sp-private-key}))
          signed-duplicate-signature (crypto/signature signed-duplicate)]
      (testing "Signatures should be different for different message payloads"
        (is (not= signed-signature signed-duplicate-signature))))))

(deftest sign-request-test-bad-params
  (testing "Signature should throw errors with bad params"
    (let [signed (coerce/->Element (coerce/->xml-string
                                    [:samlp:AuthnRequest
                                     {:xmlns:samlp                 "urn:oasis:names:tc:SAML:2.0:protocol"
                                      :ID                          1234
                                      :Version                     "2.0"
                                      :IssueInstant                1234
                                      :ProtocolBinding             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                      :ProviderName                "name"
                                      :IsPassive                   false
                                      :Destination                 "url"
                                      :AssertionConsumerServiceURL "url"}
                                     [:saml:Issuer
                                      {:xmlns:saml "urn:oasis:names:tc:SAML:2.0:assertion"}
                                      "issuer"]]))]
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"No matching signature algorithm"
           (crypto/sign signed test/sp-private-key :signature-algorithm [:rsa :crazy])))

      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"matching canonicalization algorithm"
           (crypto/sign signed test/sp-private-key :canonicalization-algorithm [:bad]))))))

(deftest has-private-key-test
  (testing "has private key"
    (is (= true (crypto/has-private-key? {:filename test/keystore-filename
                                          :password test/keystore-password
                                          :alias    "sp"})))

    (is (= true (crypto/has-private-key? test/sp-private-key)))

    (testing "has only public key"
      (is (= false (crypto/has-private-key? {:filename test/keystore-filename
                                             :password test/keystore-password
                                             :alias    "idp"}))))))
