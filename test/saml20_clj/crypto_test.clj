(ns saml20-clj.crypto-test
  (:require [clojure.test :refer :all]
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
