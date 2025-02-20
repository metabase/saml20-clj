(ns saml20-clj.sp.request-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [java-time.api :as t]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.encode-decode :as encode-decode]
            [saml20-clj.sp.request :as request]
            [saml20-clj.test :as test])
  (:import java.net.URI))

(def target-uri "http://sp.example.com/demo1/index.php?acs")

(deftest idp-redirect-response-test
  (t/with-clock (t/mock-clock (t/instant "2020-09-24T22:51:00.000Z"))
    (testing "without signature"
      (let [request (request/request
                     {:request-id "ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24"
                      :sp-name    "SP test"
                      :acs-url    "http://sp.example.com/demo1/index.php?acs"
                      :idp-url    "http://idp.example.com/SSOService.php"
                      :issuer     "http://sp.example.com/demo1/metadata.php"})]
        (is (= {:status 302,
                :body "",
                :headers
                {"Cache-control" "no-cache, no-store"
                 "Pragma" "no-cache"
                 "location" (str
                             "http://idp.example.com/SSOService.php?SAMLRequest="
                             "fVLBjtowEP0Vy%2Fckjru7bCwCoqXbIlGICNtDL5VrT4ql2E49"
                             "DqJ%2F3xBA2j2U68y8eW%2Fem%2Bn8ZFtyhIDGu5LmKaMEnPLa"
                             "uN8lfd2%2FJM90PpuitG0nFn08uB386QEjGXAOxdgoaR%2Bc8B"
                             "INCictoIhK1Itva8FTJrrgo1e%2BpWSBCCEORJ%2B8w95CqCEc"
                             "jYLX3bqkhxg7kWXYpXCStmshVd5mGqzPM%2BM0nNLu0M2lQkqW"
                             "A79xMo6Srzij3wPrenvdfsZRslqWdLv5vN5%2BWW1%2BPrNiwi"
                             "YNYx%2BYfNSMPXGmCl3oppg0T3wiGyi0UvxhgGElEc0RStrIFu"
                             "FcwR5WDqN0saSccZawIuEPe87FYy4YSxljPyiprmd%2FHMSPZt"
                             "7z6NdlCMXX%2Fb5KdqBNABXHJUejIWwGREnrisThdEq%2B3%2F"
                             "IasPSSjhh1hTex3GeUtyzo7J7zFqLUMsqzidPsDdHtJ87KVsvK"
                             "t0b9JS8%2BWBn%2FT5yn%2BVgxOmnGUdE77ECZxoCm2ezC8P7R"
                             "Zv8A&RelayState=http%3A%2F%2Fsp.example.com%2Fdemo"
                             "1%2Findex.php%3Facs")}}
               (request/idp-redirect-response request target-uri)))))
    (testing "with a signature"
      (let [request (request/request
                     {:request-id "ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24"
                      :sp-name    "SP test"
                      :acs-url    "http://sp.example.com/demo1/index.php?acs"
                      :idp-url    "http://idp.example.com/SSOService.php"
                      :issuer     "http://sp.example.com/demo1/metadata.php"
                      :credential test/sp-private-key})]
        (is (= {:status 302,
                :body "",
                :headers
                {"Cache-control" "no-cache, no-store"
                 "Pragma" "no-cache"
                 "location" (str
                             "http://idp.example.com/SSOService.php?SAMLRequest="
                             "fVLBjtowEP0Vy%2Fckjru7bCwCoqXbIlGICNtDL5VrT4ql2E49"
                             "DqJ%2F3xBA2j2U68y8eW%2Fem%2Bn8ZFtyhIDGu5LmKaMEnPLa"
                             "uN8lfd2%2FJM90PpuitG0nFn08uB386QEjGXAOxdgoaR%2Bc8B"
                             "INCictoIhK1Itva8FTJrrgo1e%2BpWSBCCEORJ%2B8w95CqCEc"
                             "jYLX3bqkhxg7kWXYpXCStmshVd5mGqzPM%2BM0nNLu0M2lQkqW"
                             "A79xMo6Srzij3wPrenvdfsZRslqWdLv5vN5%2BWW1%2BPrNiwi"
                             "YNYx%2BYfNSMPXGmCl3oppg0T3wiGyi0UvxhgGElEc0RStrIFu"
                             "FcwR5WDqN0saSccZawIuEPe87FYy4YSxljPyiprmd%2FHMSPZt"
                             "7z6NdlCMXX%2Fb5KdqBNABXHJUejIWwGREnrisThdEq%2B3%2F"
                             "IasPSSjhh1hTex3GeUtyzo7J7zFqLUMsqzidPsDdHtJ87KVsvK"
                             "t0b9JS8%2BWBn%2FT5yn%2BVgxOmnGUdE77ECZxoCm2ezC8P7R"
                             "Zv8A&RelayState=http%3A%2F%2Fsp.example.com%2Fdemo"
                             "1%2Findex.php%3Facs&SigAlg=http%3A%2F%2Fwww.w3.org"
                             "%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=cSdSQZ"
                             "qQPxv8TlUY0uLoRvuPvChJmpOTl0Ucy6zTzqWADy1jh7SfOwk8"
                             "CANyNdnCSxvXAcJgDsyO5oxonMQEpoGKCGJdFg3O8SLe5Ss%2B"
                             "Vj7vkHVFEN0PgbgtHhpnydhzR359fYIMIBMhcK4bsS9rdoLHXY"
                             "CNxI9lJlHvJXaRJCg%3D")}}
               (request/idp-redirect-response request target-uri)))))))

(deftest request-test
  (is (= [(str "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
               "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
               " AssertionConsumerServiceURL=\"http://sp.example.com/demo1/index.php?acs\""
               " Destination=\"http://idp.example.com/SSOService.php\""
               " ID=\"ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24\""
               " IsPassive=\"false\""
               " IssueInstant=\"2020-09-24T22:51:00.000Z\""
               " ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\""
               " ProviderName=\"SP test\""
               " Version=\"2.0\">")
          "  <saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">http://sp.example.com/demo1/metadata.php</saml:Issuer>"
          "  <samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\"/>"
          "</samlp:AuthnRequest>"]
         (str/split-lines
          (coerce/->xml-string
           (t/with-clock (t/mock-clock (t/instant "2020-09-24T22:51:00.000Z"))
             (request/request
              {:request-id "ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24"
               :sp-name    "SP test"
               :acs-url    "http://sp.example.com/demo1/index.php?acs"
               :idp-url    "http://idp.example.com/SSOService.php"
               :issuer     "http://sp.example.com/demo1/metadata.php"})))))))

(deftest request-validation-test
  (let [request {:acs-url    "http://sp.example.com/demo1/index.php?acs"
                 :sp-name    "My Example SP"
                 :idp-url    "http://idp.example.com/SSOService.php"
                 :issuer     "http://sp.example.com/demo1/metadata.php"
                 :request-id "_1"
                 :instant    (t/instant "2020-09-29T20:12:00.000Z")}]
    (testing "Make sure we can create a valid request given the input"
      (is (= (str "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                  "<samlp:AuthnRequest"
                  " xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
                  " AssertionConsumerServiceURL=\"http://sp.example.com/demo1/index.php?acs\""
                  " Destination=\"http://idp.example.com/SSOService.php\" ID=\"_1\""
                  " IsPassive=\"false\""
                  " IssueInstant=\"2020-09-29T20:12:00.000Z\""
                  " ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\""
                  " ProviderName=\"My Example SP\""
                  " Version=\"2.0\">"
                  "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
                  "http://sp.example.com/demo1/metadata.php"
                  "</saml:Issuer>"
                  "<samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\"/>"
                  "</samlp:AuthnRequest>")
             (-> (request/request request)
                 coerce/->xml-string
                 (str/replace #"\n\s*" "")))))
    (testing "Should validate that required params are non-blank strings"
      (doseq [k [:acs-url
                 :sp-name
                 :idp-url
                 :issuer]]
        (doseq [v [nil "" "    " false true 100]]
          (testing (format "\n%s = %s" k (pr-str v))
            (let [request (assoc request k v)]
              (is (thrown-with-msg? java.lang.AssertionError
                                    (re-pattern (format "%s is required" (name k)))
                                    (request/request request))))))))))

(deftest logout-request-test
  (let [logout-xml (t/with-clock (t/mock-clock (t/instant "2020-09-24T22:51:00.000Z"))
                     (request/make-logout-request-xml
                      {:request-id "ONELOGIN_109707f0030a5d00620c9d9df97f627afe9dcc24"
                       :user-email "user@example.com"
                       :idp-url    "http://idp.example.com/SSOService.php"
                       :issuer     "http://sp.example.com/demo1/metadata.php"}))]
    (is (= [:samlp:LogoutRequest
            {:xmlns "urn:oasis:names:tc:SAML:2.0:protocol",
             :xmlns:samlp "urn:oasis:names:tc:SAML:2.0:protocol",
             :xmlns:saml "urn:oasis:names:tc:SAML:2.0:assertion",
             :Version "2.0",
             :ID "ONELOGIN_109707f0030a5d00620c9d9df97f627afe9dcc24",
             :IssueInstant "2020-09-24T22:51:00Z",
             :Destination "http://idp.example.com/SSOService.php"}
            [:Issuer
             {:xmlns "urn:oasis:names:tc:SAML:2.0:assertion"}
             "http://sp.example.com/demo1/metadata.php"]
            [:NameID
             {:xmlns "urn:oasis:names:tc:SAML:2.0:assertion",
              :Format "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"}
             "user@example.com"]]
           logout-xml))))

(t/with-clock (t/mock-clock (t/instant "2020-09-24T22:51:00.000Z"))
  (request/logout-redirect-location
   {:issuer     "http://sp.example.com/demo1/metadata.php"
    :user-email "user@example.com"
    :idp-url    "http://idp.example.com/SSOService.php"
    :request-id "ONELOGIN_109707f0030a5d00620c9d9df97f627afe9dcc24"
    :relay-state (encode-decode/str->base64 "http://sp.example.com/demo1/metadata.php")}))

(defn parse-query-params [url]
  (let [query (-> (URI. url) .getQuery)
        pairs (str/split query #"\&")]
    (reduce (fn [params pair]
              (let [[key val] (str/split pair #"=" 2)]
                (assoc params key val)))
            {}
            pairs)))

(deftest logout-location-test
  (t/with-clock (t/mock-clock (t/instant "2020-09-24T22:51:00.000Z"))
    (let [req-id "ONELOGIN_109707f0030a5d00620c9d9df97f627afe9dcc24"
          idp-url "http://idp.example.com/SSOService.php"
          user-email "user@example.com"
          issuer "http://sp.example.com/demo1/metadata.php"
          location
          (request/logout-redirect-location
           {:issuer     issuer
            :user-email user-email
            :idp-url    idp-url
            :request-id req-id
            :relay-state (encode-decode/str->base64 issuer)})
          {:strs [SAMLRequest RelayState]} (parse-query-params location)]
      (is (= (coerce/->xml-string (request/make-logout-request-xml :request-id req-id :idp-url idp-url :issuer issuer :user-email user-email))
             (encode-decode/base64->inflate->str SAMLRequest))
          "SAMLRequest is generated correctly")
      (is (= issuer (encode-decode/base64->str RelayState))))))

(deftest idp-logout-redirect-response-test
  (t/with-clock (t/mock-clock (t/instant "2020-09-24T22:51:00.000Z"))
    (let [req-id "ONELOGIN_109707f0030a5d00620c9d9df97f627afe9dcc24"
          idp-url "http://idp.example.com/SSOService.php"
          user-email "user@example.com"
          issuer "http://sp.example.com/demo1/metadata.php"
          logout-url (request/logout-redirect-location
                      {:issuer     issuer
                       :user-email user-email
                       :idp-url    idp-url
                       :request-id req-id
                       :relay-state (encode-decode/str->base64 issuer)})
          redirect (request/idp-logout-redirect-response issuer user-email idp-url (encode-decode/str->base64 issuer) req-id)]
      (is (= logout-url (get-in redirect [:headers "Location"]))))))
