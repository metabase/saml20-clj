(ns saml20-clj.sp.response-test
  (:require [clojure.test :refer :all]
            [java-time :as t]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.sp.response :as response]
            [saml20-clj.test :as test])
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
    (let [original              (coerce/->Response (saml20-clj.test/response {:assertion-signed? true
                                                                              :assertion-encrypted? true}))
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
            :when                                (and (not (test/signed? response-map))
                                                      (not (test/malicious-signature? response-map)))]
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

(defn- validate-assertions [validator options]
  (let [response (test/response {:valid-confirmation-data? true})]
    (response/validate response nil nil (merge {:response-validators  nil
                                                :assertion-validators [validator]}
                                               options))
    :valid))

(defn- validate-assertions-bad-data [validator options]
  (let [response (test/response {:invalid-confirmation-data? true})]
    (response/validate response nil nil (merge {:response-validators  nil
                                                :assertion-validators [validator]}
                                               options))
    :valid))

(deftest validate-assertions-not-on-or-after-test
  (t/with-clock (t/mock-clock (t/instant "2020-09-24T00:00:00.000Z"))
    (is (= :valid
           (validate-assertions :not-on-or-after nil))))
  (t/with-clock (t/mock-clock (t/instant "2025-01-01T00:00:00.000Z"))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"NotOnOrAfter has passed"
         (validate-assertions :not-on-or-after nil)))
    (testing "should respect clock skew"
      ;; one year of clock skew :(
      (is (= :valid
             (validate-assertions :not-on-or-after {:allowable-clock-skew-seconds (* 60 60 24 365)}))))
    (testing "should notice if NotOnOrAfter is missing"
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"does not contain NotOnOrAfter"
           (validate-assertions-bad-data :not-on-or-after nil))))))

(deftest validate-assertions-not-before-test
  (t/with-clock (t/mock-clock (t/instant "2020-09-24T00:00:00.000Z"))
    (is (= :valid
           (validate-assertions :not-before nil))))
    (testing "should respect clock skew"
      (is (= :valid
             (validate-assertions :not-before {:allowable-clock-skew-seconds (* 60 60 24 365)}))))
  (t/with-clock (t/mock-clock (t/instant "2010-09-24T00:00:00.000Z"))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"NotBefore is in the future"
         (validate-assertions :not-before nil)))))

(deftest validate-assertions-recipient-test
  (is (= :valid
         (validate-assertions :recipient {:acs-url "http://sp.example.com/demo1/index.php?acs"})))
  (testing "wrong ACS URL"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"Recipient does not match assertion consumer service URL"
         (validate-assertions :recipient {:acs-url "http://this.is.the.wrong.url"}))))
  (testing "missing recipient"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"does not contain a Recipient"
         (validate-assertions-bad-data :recipient {:acs-url "foobar"}))))
  (testing "contains a recipient, but not checking against URL as required by spec"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"contains a Recipient but an acs-url was not passed to validate against"
         (validate-assertions :recipient nil)))))

(deftest validate-assertions-in-response-to-test
  (testing "\nchecking in-response-to attribute (solicited)"
    (is (= :valid
           (validate-assertions :in-response-to {:request-id auth-req-id, :solicited? true})))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"<SubjectConfirmationData> InResponseTo does not match request-id"
         (validate-assertions :in-response-to {:request-id "bad-request-id", :solicited? true})))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"<SubjectConfirmationData> does not contain InResponseTo"
         (validate-assertions-bad-data :in-response-to {:request-id auth-req-id, :solicited? true}))))
  (testing "\nchecking in-response-to attribute (unsolicited)"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"<SubjectConfirmationData> InResponseTo should not be present for an unsolicited request"
         (validate-assertions :in-response-to {:request-id "bad-request-id", :solicited? false})))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"<SubjectConfirmationData> InResponseTo should not be present for an unsolicited request"
         (validate-assertions :in-response-to {:solicited? false})))))

(deftest validate-assertions-address-test
  (testing "correct user agent address"
    (is (= :valid
           (validate-assertions :address {:user-agent-address "192.168.1.1"}))))
  (testing "bad user agent address"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"Address does not match user-agent-address"
         (validate-assertions :address {:user-agent-address "im.a.bad.man"})))))

(deftest validate-assertions-response-issuer-test
  (let [normal-response    (test/response {})
        response-no-issuer (test/response {:no-issuer-information? true})]
    (testing "If response has <Issuer>, it should be validated against `:issuer` (if provided)"
      (letfn [(validate [response issuer]
                (response/validate response nil nil {:response-validators  [:issuer]
                                                     :assertion-validators nil
                                                     :issuer               issuer}))]
        (testing "Correct :issuer should succeed"
          (is (instance? Response (validate normal-response "idp.example.com"))))
        (testing "If :issuer is not passed, validator should no-op"
          (is (instance? Response (validate normal-response nil))))
        (is (thrown-with-msg?
             AssertionError
             #"Expected :issuer to be a String"
             (validate normal-response 123)))
        (testing "Wrong :issuer should fail"
          (is (thrown-with-msg?
               clojure.lang.ExceptionInfo
               #"Incorrect Response <Issuer>"
               (validate normal-response "wrong.idp.issuer.com"))))
        (testing "<Response> should be allowed to have no <Issuer>"
          (is (instance? Response (validate response-no-issuer "idp.example.com"))))))

    (testing "Assertion <Issuer> should be validated against `:issuer` (if provided)"
      (letfn [(validate [response issuer]
                (response/validate response nil nil {:response-validators  []
                                                     :assertion-validators [:issuer]
                                                     :issuer               issuer}))]
        (testing "Correct :issuer should succeed"
          (is (instance? Response (validate normal-response "idp.example.com"))))
        (testing "If :issuer is not passed, validator should no-op"
          (is (instance? Response (validate normal-response nil))))
        (is (thrown-with-msg?
             AssertionError
             #"Expected :issuer to be a String"
             (validate normal-response 123)))
        (testing "Wrong :issuer should fail"
          (is (thrown-with-msg?
               clojure.lang.ExceptionInfo
               #"Incorrect Assertion <Issuer>"
               (validate normal-response "wrong.idp.issuer.com"))))
        (testing "Validation should fail if Assertion does not have an <Issuer> but :issuer is passed"
          (is (thrown-with-msg?
               clojure.lang.ExceptionInfo
               #"Assertion is missing required <Issuer> element"
               (validate response-no-issuer "idp.example.com"))))))

    (testing "Responses with no <Issuer> information should be allowed for now if :issuer is not passed"
      (is (instance? Response (response/validate response-no-issuer nil nil {:response-validators  [:issuer]
                                                                             :assertion-validators [:issuer]}))))))

(deftest Assertion->map-test
  (testing "basic checks on Assertions->map conversions"
    (doseq [{:keys [response], :as response-map} (test/responses)
            :when                                (test/valid-confirmation-data? response-map)]
      (is (= {:audiences    '("sp.example.com")
              :attrs        {"uid"                  '("test")
                             "mail"                 '("test@example.com")
                             "eduPersonAffiliation" '("users" "examplerole1")}
              :name-id      {:value  "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7",
                             :format "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"},
              :confirmation {:in-response-to  "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685",
                             :not-before      (t/instant "2019-01-18T06:21:48Z"),
                             :not-on-or-after (t/instant "2024-01-18T06:21:48Z"),
                             :address         "192.168.1.1",
                             :recipient       "http://sp.example.com/demo1/index.php?acs"}}
             (response/Assertion->map
               (first (response/opensaml-assertions (coerce/->Response response))))))))
  (testing "Attribute Nodes sharing a Name will collect all of their contained Attribute Value Nodes."
    (let [response (test/response {})]
      (is (= {"uid"                  '("test")
              "mail"                 '("test@example.com")
              ;; this key comes from an Attribute Node with two AttributeValue nodes inside
              "eduPersonAffiliation" '("users" "examplerole1")
              ;; this key is from two Attribute nodes with the same Name
              "member_of"            '("test-group1" "test-group2" "test-group3")}
             (:attrs (response/Assertion->map
                       (first (response/opensaml-assertions (coerce/->Response response))))))))))
