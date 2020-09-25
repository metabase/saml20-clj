(ns saml20-clj.crypto-test
  (:require [clojure.test :refer :all]
            [java-time :as t]
            [saml20-clj
             [crypto :as crypto]
             [test :as test]]
            [saml20-clj.sp.request :as request]))

(deftest sign-request-test
  (testing "Signature should be valid when signing request"
    (let [signed (t/with-clock (t/mock-clock (t/instant "2020-09-24T22:51:00.000Z"))
                   (request/request
                    {:request-id  "ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24"
                     :sp-name     "SP test"
                     :acs-url     "http://sp.example.com/demo1/index.php?acs"
                     :idp-url     "http://idp.example.com/SSOService.php"
                     :issuer      "http://sp.example.com/demo1/metadata.php"
                     :private-key test/sp-private-key}))]
      (is (= :valid
             (crypto/assert-signature-valid-when-present signed test/sp-cert)))
      (testing "Wrong certificate"
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo
             #"Signature does not match credential"
             (crypto/assert-signature-valid-when-present signed test/idp-cert)))))))
