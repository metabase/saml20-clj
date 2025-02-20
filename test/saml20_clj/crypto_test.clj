(ns saml20-clj.crypto-test
  (:require [clojure.test :refer :all]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.crypto :as crypto]
            [saml20-clj.test :as test]))

(deftest assert-signature-invalid-swapped-signature
  (doseq [{:keys [response], :as response-map} (test/responses)
          :when (test/malicious-signature? response-map)]
    (testing (test/describe-response-map response-map)
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"Signature does not match credential"
           (crypto/assert-signature-valid-when-present response test/idp-cert))))))

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
