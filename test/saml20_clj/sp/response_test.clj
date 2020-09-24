(ns saml20-clj.sp.response-test
  (:require [clojure.test :refer :all]
            [saml20-clj
             [coerce :as coerce]
             [test :as test]]
            [saml20-clj.sp.response :as response]))

(deftest response-status-test
  (doseq [{:keys [response], :as response-map} (test/responses)]
    (testing (test/describe-response-map response-map)
      (is (= {:in-response-to "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"
              :status         "urn:oasis:names:tc:SAML:2.0:status:Success"
              :success?       true
              :version        "2.0"
              :issue-instant  #inst "2014-07-17T01:01:48.000000000-00:00"
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
                              :not-on-or-after #inst "2024-01-18T06:21:48.000000000-00:00"
                              :address         nil
                              :recipient       "http://sp.example.com/demo1/index.php?acs"}}]
             (response/assertions response test/sp-private-key))))))

;; • Verify any signatures present on the assertion(s) or the response

(defn- validate-signature
  ([response]
   (validate-signature response test/idp-cert test/sp-private-key))

  ([response idp-cert sp-credentials]
   (response/validate-response-signature
    response
    idp-cert
    sp-credentials)))

(deftest validate-response-signature-testn
  (testing "unsigned responses should fail\n"
    (doseq [{:keys [response], :as response-map} (test/responses)
            :when                                (not (test/signed? response-map))]
      (testing (test/describe-response-map response-map)
        (is (= false
               (validate-signature response))))))
  (testing "valid signed responses should pass\n"
    (doseq [{:keys [response], :as response-map} (test/responses)
            :when                               (test/signed? response-map)]
      (testing (test/describe-response-map response-map)
        (testing "\nsignature should be valid when checking against IdP cert"
          (is (= true
                 (validate-signature response))))
        (testing "\nsignature should be invalid when checking against the wrong cert"
          (is (= false
                 ;; using SP cert for both instead
                 (validate-signature response test/sp-cert {:filename test/keystore-filename
                                                            :password test/keystore-password
                                                            :alias "sp"}))))))))

;;
;; Subject Confirmation Data Verifications
;;

(defn- response->assertions
  [response private-key]
  (let [r (coerce/->Response response)]
    (response/opensaml-assertions r private-key)))

;; TODO hardcoding these is brittle, we should pull them out of the
;; respective XML
(def acs-url "http://sp.example.com/demo1/index.php?acs")
(def auth-req-id "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685")

;; TODO there's no test for an SubjectConfirmationData field is missing (which is valid),
;; but it seems like a small case to create a whole new document for

(deftest validate-subject-confirmation-data-testn
  (testing "valid confirmation data should pass\n"
    (doseq [{:keys [response], :as response-map} (test/responses)
            :when                                (test/valid-confirmation-data? response-map)]
      (testing (test/describe-response-map response-map)
        (doseq [a (response->assertions response test/sp-private-key)]
          (testing "\nchecking not-on-or-after attribute"
            (is (= true
                   (#'response/assert-valid-not-on-or-after-attribute a))))
          (testing "\nchecking not-before attribute"
            (is (= true
                   (#'response/assert-valid-not-before-attribute a))))
          (testing "\nchecking valid recipient attribute"
            (is (= true
                   (#'response/assert-valid-recipient-attribute a acs-url))))
          (testing "\nchecking in-response-to attribute (solicited)"
            (is (= true
                   (#'response/assert-valid-in-response-to-attribute a auth-req-id true))))
          (testing "\nchecking in-response-to attribute (unsolicited)"
            (is (= false
                   (#'response/assert-valid-in-response-to-attribute a auth-req-id false))))
          (testing "\nchecking address attribute (good user agent address)"
            (is (= true
                   (#'response/assert-valid-address-attribute a "192.168.1.1"))))
          (testing "\nchecking address attribute (bad user agent address)"
            (is (= false
                   (#'response/assert-valid-address-attribute a "im.a.bad.man"))))))))

  (testing "invalid confirmation data should fail\n"
    (doseq [{:keys [response], :as response-map} (test/responses)
            :when                                (test/invalid-confirmation-data? response-map)]
      (testing (test/describe-response-map response-map)
        (doseq [a (response->assertions response test/sp-private-key)]
          (testing "\nchecking not-on-or-after attribute"
            (is (= false
                   (#'response/assert-valid-not-on-or-after-attribute a))))
          (testing "\nchecking not-before attribute"
            (is (= false
                   (#'response/assert-valid-not-before-attribute a))))
          (testing "\nchecking valid recipient attribute"
            (is (= false
                   (#'response/assert-valid-recipient-attribute a "bad-bob.com"))))
          (testing "\nchecking in-response-to attribute (solicited)"
            (is (= false
                   (#'response/assert-valid-in-response-to-attribute a "bogus_id" true))))
          (testing "\nchecking in-response-to attribute (unsolicited)"
            (is (= false
                   (#'response/assert-valid-in-response-to-attribute a "bogus_id" false)))))))))
