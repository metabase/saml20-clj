(ns saml20-clj.sp.response-test
  (:require [clojure.test :refer :all]
            [java-time :as t]
            [saml20-clj
             [coerce :as coerce]
             [test :as test]]
            [saml20-clj.sp.response :as response])
  (:import org.opensaml.saml.saml2.core.Response))

(deftest response-status-test
  (doseq [{:keys [response], :as response-map} (test/responses)]
    (testing (test/describe-response-map response-map)
      (is (= {:in-response-to "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"
              :status         "urn:oasis:names:tc:SAML:2.0:status:Success"
              :success?       true
              :version        "2.0"
              :issue-instant  (t/instant "2014-07-17T01:01:48.000Z")
              :destination    "http://sp.example.com/demo1/index.php?acs"}
             (response/response-status response))))))

(deftest assertions-test
  (doseq [{:keys [response], :as response-map} (test/responses)
          :when (not test/invalid-confirmation-data?)]
    (testing (test/describe-response-map response-map)
      (is (= [{:attrs        {"uid"                  ["test"]
                              "mail"                 ["test@example.com"]
                              "eduPersonAffiliation" ["users" "examplerole1"]}
               :audiences    ["sp.example.com"]
               :name-id      {:value  "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"
                              :format "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"}
               :confirmation {:in-response-to  "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"
                              :not-before      nil
                              :not-on-or-after (t/instant "2024-01-18T06:21:48.000Z")
                              :address         nil
                              :recipient       "http://sp.example.com/demo1/index.php?acs"}}]
             (response/assertions response test/sp-private-key))))))

;; • Verify any signatures present on the assertion(s) or the response

(deftest decrypt-response-test
  (testing "Should be able to decrypt a response"
    (let [original              (coerce/->Response (saml20-clj.test/response {:assertion-signed? true, :assertion-encrypted? true}))
          xml-before-decryption (coerce/->xml-string original)
          decrypted             (response/decrypt-response original test/sp-private-key)]
      (testing (str "\noriginal =\n" (coerce/->xml-string original))
        (testing (str "decrypted =\n" (coerce/->xml-string decrypted))
          (is (= 0
                 (count (.getEncryptedAssertions decrypted))))
          (is (= 1
                 (count (.getAssertions decrypted))))
          (testing "\noriginal object should not be modified"
            (is (= xml-before-decryption
                   (coerce/->xml-string original)))
            (is (= 0
                   (count (.getAssertions original))))
            (is (= 1
                   (count (.getEncryptedAssertions original))))))))))

(deftest assert-valid-signatures-test
  (testing "unsigned responses should fail\n"
    (doseq [{:keys [response], :as response-map} (test/responses)
            :when                                (not (test/signed? response-map))]
      (testing (test/describe-response-map response-map)
        (is (thrown-with-msg?
             java.lang.AssertionError
             #"Neither response nor assertion\(s\) are signed"
             (response/validate response test/idp-cert test/sp-private-key {:response-validators  [:signature :require-signature]
                                                                            :assertion-validators [:signature]}))))))
  (testing "valid signed responses should pass\n"
    (doseq [{:keys [response], :as response-map} (test/responses)
            :when                                (test/signed? response-map)]
      (testing (test/describe-response-map response-map)
        (testing "\nsignature should be valid when checking against IdP cert"
          (is (instance? Response
                         (response/validate response test/idp-cert test/sp-private-key {:response-validators  [:signature :require-signature]
                                                                                        :assertion-validators [:signature]}))))
        (testing "\nsignature should be invalid when checking against the wrong cert"
          (is (thrown-with-msg?
               clojure.lang.ExceptionInfo
               #"Invalid <(?:Response)|(?:Assertion)> signature"
               ;; using SP cert for both instead
               (response/validate
                response
                test/sp-cert
                {:filename test/keystore-filename
                 :password test/keystore-password
                 :alias    "sp"}
                {:response-validators  [:signature :require-signature]
                 :assertion-validators [:signature]}))))))))

(deftest assert-encrypted-assertions-test
  (testing "unencrypted assertions should fail"
    (doseq [{:keys [response], :as response-map} (test/responses)
            :when                                (not (test/assertions-encrypted? response-map))]
      (testing (test/describe-response-map response-map)
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo
             #"Unencrypted assertions present in response body"
             (response/validate response test/idp-cert test/sp-private-key {:assertion-validators [:require-encryption]})))))

    (doseq [{:keys [response], :as response-map} (test/responses)
            :when                                (test/assertions-encrypted? response-map)]
      (testing (test/describe-response-map response-map)
        (is (instance? Response
                       (response/validate response test/idp-cert test/sp-private-key {:response-validators         []
                                                                                      :assertion-validators        [:require-encryption]})))))))

(deftest test-move-validator-config-helper
  (is (= {:foo true :response-validators []}
         (#'response/move-validator-config {:response-validators [:foo]} :response-validators :foo)))
  (is (= {:foo true :response-validators [:bar]}
         (#'response/move-validator-config {:response-validators [:foo :bar]} :response-validators :foo)))
  (is (= {:response-validators [:bar]}
         (#'response/move-validator-config {:response-validators [:bar]} :response-validators :foo))))

;;
;; Subject Confirmation Data Verifications
;;

;; TODO hardcoding these is brittle, we should pull them out of the
;; respective XML
(def acs-url "http://sp.example.com/demo1/index.php?acs")
(def auth-req-id "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685")

;; TODO there's no test for an SubjectConfirmationData field is missing (which is valid), but it seems like a small
;; case to create a whole new document for

(defn- validate [validator options]
  (let [response (test/response {:valid-confirmation-data? true})]
    (response/validate response nil nil (merge {:response-validators  nil
                                                :assertion-validators [validator]}
                                               options))
    :valid))

(deftest validate-not-on-or-after-test
  (t/with-clock (t/mock-clock (t/instant "2020-09-24T00:00:00.000Z"))
    (is (= :valid
           (validate :not-on-or-after nil))))
  (t/with-clock (t/mock-clock (t/instant "2025-01-01T00:00:00.000Z"))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"NotOnOrAfter has passed"
         (validate :not-on-or-after nil)))
    (testing "should respect clock skew"
      ;; one year of clock skew :(
      (is (= :valid
             (validate :not-on-or-after {:allowable-clock-skew-seconds (* 60 60 24 365)}))))))

(deftest validate-not-before-test
  (t/with-clock (t/mock-clock (t/instant "2020-09-24T00:00:00.000Z"))
    (is (= :valid
           (validate :not-before nil))))
  #_(t/with-clock (t/mock-clock (t/instant "2010-09-24T00:00:00.000Z"))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"NotBefore is in the future"
         (validate :not-before nil))))
  ;; TODO -- test clock skew
  )

(deftest validate-recipient-test
  (is (= :valid
         (validate :recipient {:acs-url "http://sp.example.com/demo1/index.php?acs"})))
  (testing "wrong ACS URL"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"Recipient does not match assertion consumer service URL"
         (validate :recipient {:acs-url "http://this.is.the.wrong.url"})))))

(deftest validate-in-response-to-test
  (testing "\nchecking in-response-to attribute (solicited)"
    (is (= :valid
           (validate :in-response-to {:request-id auth-req-id, :solicited? true}))))
  (testing "\nchecking in-response-to attribute (unsolicited)"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"InResponseTo should not be present for an unsolicited request"
         (validate :in-response-to {:request-id auth-req-id, :solicited? false})))))

(deftest validate-address-test
  (testing "correct user agent address"
    (is (= :valid
           (validate :address {:user-agent-address "192.168.1.1"}))))
  (testing "bad user agent address"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"Address does not match user-agent-address"
         (validate :address {:user-agent-address "im.a.bad.man"})))))
