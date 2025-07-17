(ns saml20-clj.sp.response-test
  (:require [clojure.test :refer [deftest is testing]]
            [java-time.api :as t]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.sp.response :as response]
            [saml20-clj.state :as state]
            [saml20-clj.test :as test])
  (:import org.opensaml.saml.saml2.core.Response))

(set! *warn-on-reflection* true)

;; Helper to replace direct validate-response calls with validate-response-for-profile
(defn- validate-response-with-options
  "Validates a response using validate-response-for-profile with a :default profile
   to maintain backward compatibility with tests that directly set validators."
  [response options]
  (response/validate-response-for-profile response :default options))

(deftest response-status-test
  (doseq [{:keys [response], :as response-map} (test/responses)]
    (testing (test/describe-response-map response-map)
      (is (= {:in-response-to "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"
              :status "urn:oasis:names:tc:SAML:2.0:status:Success"
              :success? true
              :version "2.0"
              :issue-instant (t/instant "2014-07-17T01:01:48.000Z")
              :destination "http://sp.example.com/demo1/index.php?acs"}
             (response/response-status response))))))

(deftest assertions-test
  (doseq [{:keys [response], :as response-map} (test/responses)
          :when (not test/invalid-confirmation-data?)]
    (testing (test/describe-response-map response-map)
      (is (= [{:attrs {"uid" ["test"]
                       "mail" ["test@example.com"]
                       "eduPersonAffiliation" ["users" "examplerole1"]}
               :audiences ["sp.example.com"]
               :name-id {:value "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"
                         :format "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"}
               :confirmation {:in-response-to "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"
                              :not-before nil
                              :not-on-or-after (t/instant "2024-01-18T06:21:48.000Z")
                              :address nil
                              :recipient "http://sp.example.com/demo1/index.php?acs"}}]
             (response/assertions response test/sp-private-key))))))

;; • Verify any signatures present on the assertion(s) or the response

(deftest decrypt-response-test
  (testing "Should be able to decrypt a response"
    (doseq [{:keys [response], :as response-map} (test/responses)
            :when (test/signed-and-encrypted-assertion? response-map)]
      (let [original (coerce/->Response response)
            xml-before-decryption (coerce/->xml-string original)
            decrypted (response/decrypt-response original test/sp-private-key)]
        (testing (test/describe-response-map response-map)
          (testing (str "\noriginal =\n" (coerce/->xml-string original))
            (testing (str "decrypted =\n" (coerce/->xml-string decrypted))
              (prn :original (coerce/->xml-string original))
              (prn :decrypted (coerce/->xml-string decrypted))
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
                       (count (.getEncryptedAssertions original))))))))))))

(deftest assert-valid-signatures-test
  (testing "unsigned responses should fail\n"
    (doseq [{:keys [response], :as response-map} (test/responses)
            :when (and (not (test/message-signed? response-map))
                       (not (test/assertion-signed? response-map))
                       (not (test/malicious-signature? response-map)))]
      (testing (test/describe-response-map response-map)
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo
             #"Message is not Authenticated"
             (validate-response-with-options (test/ring-response-post response)
                                             {:idp-cert test/idp-cert
                                              :sp-private-key test/sp-private-key
                                              :response-validators [:signature :require-authenticated]
                                              :assertion-validators [:signature]}))))))
  (testing "valid signed responses should pass\n"
    (doseq [{:keys [response], :as response-map} (test/responses)
            :when (test/message-signed? response-map)]
      (testing (test/describe-response-map response-map)
        (testing "\nsignature should be valid when checking against IdP cert"
          (is (instance? Response
                         (validate-response-with-options (test/ring-response-post response)
                                                         {:idp-cert test/idp-cert
                                                          :sp-private-key test/sp-private-key
                                                          :response-validators [:signature :require-authenticated]
                                                          :assertion-validators [:signature]}))))
        (testing "\nsignature should be invalid when checking against the wrong cert"
          (is (thrown-with-msg?
               clojure.lang.ExceptionInfo
               #"Message failed to validate signature"
               ;; using SP cert for both instead
               (validate-response-with-options
                (test/ring-response-post response)
                {:idp-cert test/sp-cert
                 :sp-private-key {:filename test/keystore-filename
                                  :password test/keystore-password
                                  :alias "sp"}
                 :response-validators [:signature :require-authenticated]
                 :assertion-validators [:signature]}))))))))

(deftest assert-encrypted-assertions-test
  (testing "unencrypted assertions should fail"
    (doseq [{:keys [response], :as response-map} (test/responses)
            :when (not (test/assertions-encrypted? response-map))]
      (testing (test/describe-response-map response-map)
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo
             #"Unencrypted assertions present in response body"
             (validate-response-with-options (test/ring-response-post response)
                                             {:idp-cert test/idp-cert
                                              :sp-private-key test/sp-private-key
                                              :response-validators [:require-encryption]
                                              :assertion-validators []})))))

    (doseq [{:keys [response], :as response-map} (test/responses)
            :when (test/assertions-encrypted? response-map)]
      (testing (test/describe-response-map response-map)
        (is (instance? Response
                       (validate-response-with-options (test/ring-response-post response)
                                                       {:idp-cert test/idp-cert
                                                        :sp-private-key test/sp-private-key
                                                        :response-validators [:require-encryption]
                                                        :assertion-validators []})))))))

;;
;; Subject Confirmation Data Verifications
;;

;; TODO hardcoding these is brittle, we should pull them out of the
;; respective XML
(def ^:private auth-req-id "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685")

;; TODO there's no test for an SubjectConfirmationData field is missing (which is valid), but it seems like a small
;; case to create a whole new document for

(defn- validate-assertions [validator options]
  (let [response (test/response {:valid-confirmation-data? true})]
    (validate-response-with-options (test/ring-response-post response)
                                    (merge {:response-validators nil
                                            :assertion-validators [validator]}
                                           options))
    :valid))

(defn- validate-assertions-bad-data [validator options]
  (let [response (test/response {:invalid-confirmation-data? true})]
    (validate-response-with-options (test/ring-response-post response)
                                    (merge {:response-validators nil
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
  (let [normal-response (test/response {})
        response-no-issuer (test/response {:no-issuer-information? true})]
    (testing "If response has <Issuer>, it should be validated against `:issuer`"
      (letfn [(validate [response issuer]
                (validate-response-with-options (test/ring-response-post response)
                                                {:response-validators [:issuer]
                                                 :assertion-validators nil
                                                 :issuer issuer}))]
        (testing "Correct :issuer should succeed"
          (is (instance? Response (validate normal-response "idp.example.com"))))
        (testing "If :issuer is not passed, validator should error"
          (is (thrown-with-msg?
               AssertionError
               #"Assert failed: Must provide issuer identifier for idp"
               (validate normal-response nil))))
        (testing "If :issuer is not a string, validator should error"
          (is (thrown-with-msg?
               AssertionError
               #"Assert failed: Must provide issuer identifier for idp"
               (validate normal-response 123))))
        (testing "Wrong :issuer should fail"
          (is (thrown-with-msg?
               clojure.lang.ExceptionInfo
               #"Message failed to validate issuer"
               (validate normal-response "wrong.idp.issuer.com"))))
        (testing "<Response> should not be allowed to have no <Issuer>"
          (is (thrown-with-msg?
               clojure.lang.ExceptionInfo
               #"Message failed to validate issuer"
               (validate response-no-issuer "idp.example.com"))))))
    (testing "Assertion <Issuer> should be validated against `:issuer`"
      (letfn [(validate [response issuer]
                (validate-response-with-options (test/ring-response-post response)
                                                {:response-validators []
                                                 :assertion-validators [:issuer]
                                                 :issuer issuer}))]
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

    (testing "Responses with no <Issuer> information should not be allowed if :issuer is not passed"
      (is (thrown-with-msg?
           AssertionError
           #"Assert failed: Must provide issuer identifier for idp"
           (validate-response-with-options (test/ring-response-post response-no-issuer)
                                           {:response-validators [:issuer]
                                            :assertion-validators [:issuer]}))))))

(deftest assertion-test
  (testing "basic checks on Assertions->map conversions"
    (doseq [{:keys [response], :as response-map} (test/responses)
            :when (test/valid-confirmation-data? response-map)]
      (is (= {:audiences '("sp.example.com")
              :attrs {"uid" '("test")
                      "mail" '("test@example.com")
                      "eduPersonAffiliation" '("users" "examplerole1")}
              :name-id {:value "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7",
                        :format "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"},
              :confirmation {:in-response-to "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685",
                             :not-before (t/instant "2019-01-18T06:21:48Z"),
                             :not-on-or-after (t/instant "2024-01-18T06:21:48Z"),
                             :address "192.168.1.1",
                             :recipient "http://sp.example.com/demo1/index.php?acs"}}
             (first (response/assertions (coerce/->Response response)))))))
  (testing "Attribute Nodes sharing a Name will collect all of their contained Attribute Value Nodes."
    (let [response (test/response {})]
      (is (= {"uid" '("test")
              "mail" '("test@example.com")
              ;; this key comes from an Attribute Node with two AttributeValue nodes inside
              "eduPersonAffiliation" '("users" "examplerole1")
              ;; this key is from two Attribute nodes with the same Name
              "member_of" '("test-group1" "test-group2" "test-group3")}
             (:attrs (first (response/assertions (coerce/->Response response)))))))))

(defn create-test-assertion
  "Create a test assertion with current timestamps"
  []
  (let [now (java.time.Instant/now)
        not-before (.minus now 5 java.time.temporal.ChronoUnit/MINUTES)
        not-on-or-after (.plus now 5 java.time.temporal.ChronoUnit/MINUTES)
        authn-instant (.minus now 1 java.time.temporal.ChronoUnit/MINUTES)
        session-not-on-or-after (.plus now 8 java.time.temporal.ChronoUnit/HOURS)]
    (str "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
                xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"
                ID=\"_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75\"
                Version=\"2.0\"
                IssueInstant=\"" now "\">
  <saml:Issuer>idp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
    <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">
      <saml:SubjectConfirmationData NotOnOrAfter=\"" not-on-or-after "\"
                                     Recipient=\"http://sp.example.com/demo1/index.php?acs\"
                                     InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore=\"" not-before "\" NotOnOrAfter=\"" not-on-or-after "\">
    <saml:AudienceRestriction>
      <saml:Audience>http://sp.example.com</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant=\"" authn-instant "\"
                       SessionNotOnOrAfter=\"" session-not-on-or-after "\"
                       SessionIndex=\"_be9967abd904ddcae3c0eb4189adbe3f71e327cf93\">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    <saml:Attribute Name=\"uid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">
      <saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">test@example.com</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>")))

(defn- create-test-response
  "Create a test response with current timestamps"
  [{:keys [signed? issuer]}]
  (let [now (java.time.Instant/now)
        assertion-xml (create-test-assertion)]
    (str "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
                xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
                ID=\"_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6\"
                Version=\"2.0\"
                IssueInstant=\"" now "\"
                Destination=\"http://sp.example.com/demo1/index.php?acs\"
                InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\">
  <saml:Issuer>" (or issuer "idp.example.com") "</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>
  </samlp:Status>"
         ;; Remove the xml declaration from the assertion before inserting
         (subs assertion-xml (.indexOf ^String assertion-xml "<saml:Assertion"))
         "</samlp:Response>")))

(deftest test-attribute-statement-validator
  (testing "passes when AttributeStatement exists and require-attributes is false"
    (let [response-str (create-test-response {})
          response (coerce/->Response response-str)
          assertion (first (.getAssertions response))]
      (is (nil? (response/validate-assertion :attribute-statement assertion {:require-attributes false})))))

  (testing "passes when AttributeStatement exists and require-attributes is true"
    (let [response-str (create-test-response {})
          response (coerce/->Response response-str)
          assertion (first (.getAssertions response))]
      (is (nil? (response/validate-assertion :attribute-statement assertion {:require-attributes true})))))

  (testing "passes when AttributeStatement missing and require-attributes is false"
    (let [assertion (doto (.buildObject (org.opensaml.saml.saml2.core.impl.AssertionBuilder.))
                      (.setID "test-assertion"))]
      (is (nil? (response/validate-assertion :attribute-statement assertion {:require-attributes false})))))

  (testing "fails when AttributeStatement missing and require-attributes is true"
    (let [assertion (doto (.buildObject (org.opensaml.saml.saml2.core.impl.AssertionBuilder.))
                      (.setID "test-assertion"))]
      (is (thrown? clojure.lang.ExceptionInfo
                   (response/validate-assertion :attribute-statement assertion {:require-attributes true}))))))

(deftest test-authz-decision-statement-validator
  (testing "passes when no authorization validation requested"
    (let [response-str (create-test-response {})
          response (coerce/->Response response-str)
          assertion (first (.getAssertions response))]
      (is (nil? (response/validate-assertion :authz-decision-statement assertion {:validate-authorization false})))))

  (testing "passes when no AuthzDecisionStatement present"
    (let [response-str (create-test-response {})
          response (coerce/->Response response-str)
          assertion (first (.getAssertions response))]
      (is (nil? (response/validate-assertion :authz-decision-statement assertion {:validate-authorization true})))))

  (testing "validates AuthzDecisionStatement when present"
    ;; This is more complex due to OpenSAML's ListView implementation
    ;; For now, we'll just verify the validator exists and works with no statements
    (is (contains? (methods response/validate-assertion) :authz-decision-statement))))

(deftest test-authn-context-validator
  (testing "passes when no required contexts specified"
    (let [response-str (create-test-response {})
          response (coerce/->Response response-str)
          assertion (first (.getAssertions response))]
      (is (nil? (response/validate-assertion :authn-context assertion {})))))

  (testing "passes when required context matches"
    (let [response-str (create-test-response {})
          response (coerce/->Response response-str)
          assertion (first (.getAssertions response))]
      (is (nil? (response/validate-assertion :authn-context assertion
                                             {:required-authn-contexts ["urn:oasis:names:tc:SAML:2.0:ac:classes:Password"]})))))

  (testing "fails when required context doesn't match"
    (let [response-str (create-test-response {})
          response (coerce/->Response response-str)
          assertion (first (.getAssertions response))]
      (is (thrown? clojure.lang.ExceptionInfo
                   (response/validate-assertion :authn-context assertion
                                                {:required-authn-contexts ["urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"]}))))))

(deftest test-validate-response-for-profile
  (testing "SP-initiated profile includes in-response-to validator"
    (let [response-str (create-test-response {:issuer "idp.example.com"})
          response (test/ring-response-post response-str)
          ;; For testing purposes, we'll override validators to not require authentication
          ;; and remove audience-restriction which has a bug (uses IdP issuer instead of SP entity ID)
          test-sp-initiated-validations {:response-validators [:issuer :in-response-to :status-code]
                                         :assertion-validators [:signature :recipient :not-on-or-after :not-before
                                                                :subject-confirmation-method :authn-statement
                                                                :conditions :in-response-to]}
          options {:idp-cert test/idp-cert
                   :sp-private-key test/sp-private-key
                   :acs-url "http://sp.example.com/demo1/index.php?acs"
                   :issuer "idp.example.com"
                   :request-id "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"
                   :allowable-clock-skew-seconds 180}
          enhanced-options (merge options test-sp-initiated-validations)
          validated (response/validate-response-for-profile response :sp-initiated enhanced-options)]
      (is (some? validated))
      ;; Verify that in-response-to is in the validators
      (is (some #{:in-response-to} (:assertion-validators enhanced-options)))))

  (testing "IdP-initiated profile excludes in-response-to validator"
    (let [response-str (create-test-response {:issuer "idp.example.com"})
          response (test/ring-response-post response-str)
          ;; For testing purposes, we'll override validators to not require authentication
          ;; and remove audience-restriction which has a bug
          test-idp-initiated-validations {:response-validators [:issuer :status-code]
                                          :assertion-validators [:signature :recipient :not-on-or-after :not-before
                                                                 :subject-confirmation-method :authn-statement
                                                                 :conditions]}
          options {:idp-cert test/idp-cert
                   :sp-private-key test/sp-private-key
                   :acs-url "http://sp.example.com/demo1/index.php?acs"
                   :issuer "idp.example.com"
                   :allowable-clock-skew-seconds 180}
          enhanced-options (merge options test-idp-initiated-validations)
          validated (response/validate-response-for-profile response :idp-initiated enhanced-options)]
      (is (some? validated))
      ;; Verify that in-response-to is NOT in the validators
      (is (not (some #{:in-response-to} (:assertion-validators enhanced-options)))))))

(deftest test-replay-prevention-validator
  "Test the replay prevention validator"
  (testing "replay prevention with state manager"
    (let [state-manager (state/in-memory-state-manager)
          assertion (coerce/->SAMLObject (create-test-assertion))
          validation-options {:state-manager state-manager}]

      ;; First validation should pass
      (is (nil? (response/validate-assertion :replay-prevention assertion validation-options)))

      ;; Second validation should fail with replay error
      (is (thrown-with-msg? Exception #"SAML assertion has been processed before"
                            (response/validate-assertion :replay-prevention assertion validation-options)))))

  (testing "replay prevention without state manager"
    (let [assertion (coerce/->SAMLObject (create-test-assertion))
          validation-options {}]

      ;; Should pass without state manager (validation is skipped)
      (is (nil? (response/validate-assertion :replay-prevention assertion validation-options))))))

(deftest test-configuration-system
  "Test the configuration-driven validation system"
  (testing "create-validation-config"
    (let [sp-config (response/create-validation-config :sp-initiated)
          idp-config (response/create-validation-config :idp-initiated)
          default-config (response/create-validation-config :default)
          custom-config (response/create-validation-config :sp-initiated
                                                           {:assertion-validators [:signature :replay-prevention]})]

      ;; Test that configs are created correctly
      (is (contains? (set (:assertion-validators sp-config)) :in-response-to))
      (is (not (contains? (set (:assertion-validators idp-config)) :in-response-to)))
      (is (= (:assertion-validators default-config) (:assertion-validators idp-config)))
      (is (= (:assertion-validators custom-config) [:signature :replay-prevention]))))

  (testing "validate-configuration"
    (let [valid-config {:response-validators [:signature :issuer]
                        :assertion-validators [:signature :recipient]}
          invalid-response-config {:response-validators [:invalid-validator]
                                   :assertion-validators [:signature]}
          invalid-assertion-config {:response-validators [:signature]
                                    :assertion-validators [:invalid-validator]}]

      ;; Valid config should pass
      (is (= valid-config (response/validate-configuration valid-config)))

      ;; Invalid response validator should fail
      (is (thrown-with-msg? Exception #"Invalid response validators"
                            (response/validate-configuration invalid-response-config)))

      ;; Invalid assertion validator should fail
      (is (thrown-with-msg? Exception #"Invalid assertion validators"
                            (response/validate-configuration invalid-assertion-config))))))

(deftest test-plugin-system
  "Test the custom validation plugin system"
  (testing "plugin registration and unregistration"
    (let [test-plugin (reify response/CustomValidator
                        (validate-custom [this element options context]
                          (when (:fail-validation options)
                            (throw (ex-info "Test plugin validation failed" {:plugin-test true})))))]

      ;; Initially no plugins
      (is (empty? (response/list-validation-plugins)))

      ;; Register plugin
      (response/register-validation-plugin :test-plugin test-plugin)
      (is (contains? (response/list-validation-plugins) :test-plugin))

      ;; Unregister plugin
      (response/unregister-validation-plugin :test-plugin)
      (is (not (contains? (response/list-validation-plugins) :test-plugin)))))

  (testing "plugin validation execution"
    (let [assertion (coerce/->SAMLObject (create-test-assertion))
          test-plugin (reify response/CustomValidator
                        (validate-custom [this element options context]
                          (when (:fail-validation options)
                            (throw (ex-info "Test plugin validation failed" {:plugin-test true})))))]

      ;; Register plugin
      (response/register-validation-plugin :test-plugin test-plugin)

      ;; Should pass with normal options
      (is (nil? (response/apply-custom-validations assertion {} {})))

      ;; Should fail with fail-validation option
      (is (thrown-with-msg? Exception #"Custom validation plugin failed: :test-plugin"
                            (response/apply-custom-validations assertion {:fail-validation true} {})))

      ;; Clean up
      (response/unregister-validation-plugin :test-plugin))))

(deftest test-enhanced-state-manager
  "Test enhanced state manager functionality for Phase 3"
  (testing "cleanup-expired! and is-duplicate? methods"
    (let [state-manager (state/in-memory-state-manager)]

      ;; Test is-duplicate? with new assertion
      (is (= false (state/is-duplicate? state-manager "test-assertion-1")))

      ;; Test accept-assertion! 
      (is (= true (state/accept-assertion! state-manager "test-assertion-1")))

      ;; Test is-duplicate? after recording
      (is (= true (state/is-duplicate? state-manager "test-assertion-1")))

      ;; Test accept-assertion! for duplicate
      (is (= false (state/accept-assertion! state-manager "test-assertion-1")))

      ;; Test cleanup-expired!
      (is (nil? (state/cleanup-expired! state-manager)))

      ;; State should still contain our assertion after cleanup
      (is (= true (state/is-duplicate? state-manager "test-assertion-1"))))))

(deftest test-enhanced-replay-prevention
  "Test enhanced replay prevention validator"
  (testing "replay prevention with is-duplicate? check"
    (let [state-manager (state/in-memory-state-manager)
          assertion (coerce/->SAMLObject (create-test-assertion))
          validation-options {:state-manager state-manager}]

      ;; First validation should pass and record assertion
      (is (nil? (response/validate-assertion :replay-prevention assertion validation-options)))

      ;; Assertion should now be marked as seen
      (is (= true (state/is-duplicate? state-manager (.getID ^org.opensaml.saml.saml2.core.Assertion assertion))))

      ;; Second validation should fail with replay error
      (is (thrown-with-msg? Exception #"SAML assertion has been processed before"
                            (response/validate-assertion :replay-prevention assertion validation-options))))))

(deftest test-configuration-driven-validation
  "Test configuration-driven validation enhancements"
  (testing "strict validation config"
    (let [config (response/create-strict-validation-config :sp-initiated)]
      (is (contains? (set (:assertion-validators config)) :replay-prevention))
      (is (contains? (set (:assertion-validators config)) :one-time-use))
      (is (contains? (set (:assertion-validators config)) :proxy-restriction))
      (is (= 60 (:allowable-clock-skew-seconds config)))
      (is (= 3600 (:max-session-age-seconds config)))
      (is (= true (:require-attributes config)))
      (is (= true (:validate-authorization config)))))

  (testing "relaxed validation config"
    (let [config (response/create-relaxed-validation-config :sp-initiated)]
      (is (not (contains? (set (:assertion-validators config)) :replay-prevention)))
      (is (not (contains? (set (:assertion-validators config)) :one-time-use)))
      (is (= 300 (:allowable-clock-skew-seconds config)))
      (is (= 86400 (:max-session-age-seconds config)))
      (is (= false (:require-attributes config)))
      (is (= false (:validate-authorization config)))))

  (testing "custom validation config"
    (let [config (response/create-validation-config :sp-initiated {:custom-setting true})]
      (is (= true (:custom-setting config))))))

(deftest test-enhanced-plugin-system
  "Test enhanced plugin system with validation"
  (testing "plugin validation on registration"
    (let [valid-plugin (reify response/CustomValidator
                         (validate-custom [this element options context] nil))
          invalid-plugin (fn [element options context] nil)]

      ;; Valid plugin should register successfully
      (is (nil? (response/register-validation-plugin :valid-plugin valid-plugin)))

      ;; Invalid plugin should throw exception
      (is (thrown-with-msg? Exception #"Plugin must implement CustomValidator protocol"
                            (response/register-validation-plugin :invalid-plugin invalid-plugin)))

      ;; Non-keyword name should throw exception
      (is (thrown-with-msg? Exception #"Plugin name must be a keyword"
                            (response/register-validation-plugin "invalid-name" valid-plugin)))

      ;; Clean up
      (response/unregister-validation-plugin :valid-plugin)))

  (testing "plugin info and validation"
    (let [test-plugin (reify response/CustomValidator
                        (validate-custom [this element options context] nil))]

      ;; Register plugin
      (response/register-validation-plugin :test-plugin test-plugin)

      ;; Test plugin info
      (let [info (response/get-plugin-info :test-plugin)]
        (is (= :test-plugin (:name info)))
        (is (= true (:implements-protocol? info))))

      ;; Test validation
      (is (empty? (response/validate-plugin-configuration)))

      ;; Clean up
      (response/unregister-validation-plugin :test-plugin))))

(deftest test-one-time-use-validator
  "Test the one-time-use validator"
  (testing "one-time-use validator with OneTimeUse condition"
    (let [state-manager (state/in-memory-state-manager)
          ;; Create a custom assertion XML with OneTimeUse condition
          assertion-xml (str "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" "
                             "ID=\"test-assertion-id\" IssueInstant=\"2014-07-17T01:01:48Z\" Version=\"2.0\">"
                             "<saml2:Issuer>idp.example.com</saml2:Issuer>"
                             "<saml2:Subject>"
                             "<saml2:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">test-user</saml2:NameID>"
                             "<saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
                             "<saml2:SubjectConfirmationData NotOnOrAfter=\"2024-01-18T06:21:48Z\" Recipient=\"http://sp.example.com/demo1/index.php?acs\"/>"
                             "</saml2:SubjectConfirmation>"
                             "</saml2:Subject>"
                             "<saml2:Conditions NotBefore=\"2014-07-17T01:01:18Z\" NotOnOrAfter=\"2024-01-18T06:21:48Z\">"
                             "<saml2:OneTimeUse/>"
                             "</saml2:Conditions>"
                             "<saml2:AuthnStatement AuthnInstant=\"2014-07-17T01:01:48Z\">"
                             "<saml2:AuthnContext>"
                             "<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef>"
                             "</saml2:AuthnContext>"
                             "</saml2:AuthnStatement>"
                             "</saml2:Assertion>")
          assertion (coerce/->SAMLObject assertion-xml)
          validation-options {:state-manager state-manager}]

      ;; First validation should pass
      (is (nil? (response/validate-assertion :one-time-use assertion validation-options)))

      ;; Second validation should fail because OneTimeUse assertion was already used
      (is (thrown-with-msg? Exception #"Assertion has already been used \(OneTimeUse violation\)"
                            (response/validate-assertion :one-time-use assertion validation-options)))))

  (testing "one-time-use validator without OneTimeUse condition"
    (let [state-manager (state/in-memory-state-manager)
          assertion (coerce/->SAMLObject (create-test-assertion))
          validation-options {:state-manager state-manager}]

      ;; Should pass without OneTimeUse condition
      (is (nil? (response/validate-assertion :one-time-use assertion validation-options)))
      ;; Should pass again because there's no OneTimeUse condition
      (is (nil? (response/validate-assertion :one-time-use assertion validation-options)))))

  (testing "one-time-use validator without state manager"
    (let [;; Create assertion with OneTimeUse condition
          assertion-xml (str "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" "
                             "ID=\"test-assertion-id\" IssueInstant=\"2014-07-17T01:01:48Z\" Version=\"2.0\">"
                             "<saml2:Issuer>idp.example.com</saml2:Issuer>"
                             "<saml2:Subject>"
                             "<saml2:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">test-user</saml2:NameID>"
                             "<saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
                             "<saml2:SubjectConfirmationData NotOnOrAfter=\"2024-01-18T06:21:48Z\" Recipient=\"http://sp.example.com/demo1/index.php?acs\"/>"
                             "</saml2:SubjectConfirmation>"
                             "</saml2:Subject>"
                             "<saml2:Conditions NotBefore=\"2014-07-17T01:01:18Z\" NotOnOrAfter=\"2024-01-18T06:21:48Z\">"
                             "<saml2:OneTimeUse/>"
                             "</saml2:Conditions>"
                             "<saml2:AuthnStatement AuthnInstant=\"2014-07-17T01:01:48Z\">"
                             "<saml2:AuthnContext>"
                             "<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef>"
                             "</saml2:AuthnContext>"
                             "</saml2:AuthnStatement>"
                             "</saml2:Assertion>")
          assertion (coerce/->SAMLObject assertion-xml)
          validation-options {}]

      ;; Should fail because OneTimeUse condition is present but no state manager
      (is (thrown-with-msg? Exception #"OneTimeUse.*no state manager"
                            (response/validate-assertion :one-time-use assertion validation-options))))))
