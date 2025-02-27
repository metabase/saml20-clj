(ns saml20-clj.state-test
  (:require [clojure.test :refer :all]
            [java-time.api :as t]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.sp.request :as request]
            [saml20-clj.sp.response :as response]
            [saml20-clj.state :as state]
            [saml20-clj.test :as test]))

(deftest in-memory-state-manager-test
  (let [m (state/in-memory-state-manager)]
    (t/with-clock (t/mock-clock (t/instant "2020-09-25T08:00:00.000Z"))
      (testing "record some IDs"
        (state/record-request! m 1)
        (state/record-request! m 2)
        (is (= [[(t/instant "2020-09-25T08:00:00Z") #{1 2}]]
               @m))))
    (testing "Move forward to t+1 minute"
      (t/with-clock (t/mock-clock (t/instant "2020-09-25T08:01:00.000Z"))
        (testing "consume one of the IDs"
          (state/accept-response! m 2)
          (is (= [[(t/instant "2020-09-25T08:00:00Z") #{1}]]
                 @m)))
        (testing "trying to consume the ID a second time should throw an Exception"
          (is (thrown-with-msg?
               clojure.lang.ExceptionInfo
               #"Invalid request ID"
               (state/accept-response! m 2))))
        (testing "Add a few more request IDs"
          (state/record-request! m 3)
          (state/record-request! m 4)
          (is (= [[(t/instant "2020-09-25T08:00:00Z") #{1 3 4}]]
                 @m)))))
    (testing "Move forward to t+3 minutes"
      (t/with-clock (t/mock-clock (t/instant "2020-09-25T08:03:00.000Z"))
        (testing "Add an ID. Buckets should get rotated"
          (state/record-request! m 5)
          (is (= [[(t/instant "2020-09-25T08:03:00.000Z") #{5}]
                  [(t/instant "2020-09-25T08:00:00Z") #{1 3 4}]
                  nil]
                 @m)))
        (testing "Should be able to consume ID in other bucket"
          (state/accept-response! m 3)
          (is (= [[(t/instant "2020-09-25T08:03:00.000Z") #{5}]
                  [(t/instant "2020-09-25T08:00:00Z") #{1 4}]
                  nil]
                 @m)))))
    (testing "Move forward to t+6 minutes"
      (t/with-clock (t/mock-clock (t/instant "2020-09-25T08:06:00.000Z"))
        (testing "Consume an ID. Buckets should get rotated"
          (state/accept-response! m 1)
          (is (= [[(t/instant "2020-09-25T08:06:00.000Z") #{}]
                  [(t/instant "2020-09-25T08:03:00.000Z") #{5}]
                  [(t/instant "2020-09-25T08:00:00Z") #{4}]]
                 @m)))
        (testing "Add some more IDs"
          (state/record-request! m 6)
          (state/record-request! m 7)
          (is (= [[(t/instant "2020-09-25T08:06:00.000Z") #{6 7}]
                  [(t/instant "2020-09-25T08:03:00.000Z") #{5}]
                  [(t/instant "2020-09-25T08:00:00Z") #{4}]]
                 @m)))))
    (testing "Move forward to t+9 minutes"
      (t/with-clock (t/mock-clock (t/instant "2020-09-25T08:09:00.000Z"))
        (testing "Attempt to consume now-ancient ID"
          (is (thrown-with-msg?
               clojure.lang.ExceptionInfo
               #"Invalid request ID"
               (state/accept-response! m 4))))
        (testing "(buckets won't have been rotated because an Exception was thrown)"
          (is (= [[(t/instant "2020-09-25T08:06:00.000Z") #{6 7}]
                  [(t/instant "2020-09-25T08:03:00.000Z") #{5}]
                  [(t/instant "2020-09-25T08:00:00Z") #{4}]]
                 @m)))
        (testing "adding a new ID will cause the old bucket to get dropped"
          (state/record-request! m 8)
          (is (= [[(t/instant "2020-09-25T08:09:00.000Z") #{8}]
                  [(t/instant "2020-09-25T08:06:00.000Z") #{6 7}]
                  [(t/instant "2020-09-25T08:03:00.000Z") #{5}]]
                 @m)))))))

(deftest e2e-test
  (let [m (state/in-memory-state-manager)]
    (t/with-clock (t/mock-clock (t/instant "2020-09-25T08:00:00.000Z"))
      (testing "generate request"
        (request/idp-redirect-response
         {:request-id    "ABC"
          :sp-name       "SP test"
          :acs-url       "http://sp.example.com/demo1/index.php?acs"
          :idp-url       "http://idp.example.com/SSOService.php"
          :issuer        "http://sp.example.com/demo1/metadata.php"
          :state-manager m}))
      (testing "ID should be recorded"
        (is (= [[(t/instant "2020-09-25T08:00:00Z") #{"ABC"}]]
               @m)))
      (testing "Handle response"
        (letfn [(handle-response! []
                  (-> (str "<samlp:Response"
                           " xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
                           " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\""
                           " InResponseTo=\"ABC\""
                           " Version=\"2.0\">"
                           "</samlp:Response>")
                      coerce/->Response
                      test/ring-response-post
                      (response/validate-response {:state-manager m, :response-validators []})))]
          (handle-response!)
          (testing "ID should be removed"
            (is (= [[(t/instant "2020-09-25T08:00:00Z") #{}]]
                   @m)))
          (testing "Shouldn't be allowed to use ID not recorded in state"
            (is (thrown-with-msg?
                 clojure.lang.ExceptionInfo
                 #"Invalid request ID"
                 (handle-response!)))))))))
