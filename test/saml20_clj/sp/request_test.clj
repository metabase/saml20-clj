(ns saml20-clj.sp.request-test
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [java-time.api :as t]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.encode-decode :as encode-decode]
            [saml20-clj.sp.request :as request]
            [saml20-clj.test :as test]))

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

(deftest idp-logout-redirect-response-test
  (t/with-clock (t/mock-clock (t/instant "2020-09-24T22:51:00.000Z"))
    (let [req-id "ONELOGIN_109707f0030a5d00620c9d9df97f627afe9dcc24"
          idp-url "http://idp.example.com/SSOService.php"
          user-email "user@example.com"
          issuer "http://sp.example.com/demo1/metadata.php"]
      (testing "without signing"

        (is (= {:status 302
                :headers {"Cache-control" "no-cache, no-store"
                          "Pragma" "no-cache"
                          "location" (str
                                      "http://idp.example.com/SSOService.php?SAMLRequest="
                                      "nZHLTsMwEEV%2FJfK%2BycS0DbGaFKQAihRaiRQWbJBlT9pI8Y"
                                      "PYqfr5pA%2BkwoIFO4%2Bse88czWJ5UF2wx961RmckDoEEqIWR"
                                      "rd5m5HXzOLkly3zhuOosq8zWDP4FPwd0PhiD2rHTT0aGXjPDXe"
                                      "uY5god84LV988VoyEw2xtvhOlIUIy5VnN%2FYu28tyyKWmlDPH"
                                      "BlOwyFUVFdr2vs963A0O4sCcoiI%2BvVQ7V%2BKlcfMaQJJA3A"
                                      "DfCZBJhTEKlMZZMmzZwmvMFUCkGnY8y5AUvtPNc%2BIxQoTCCd"
                                      "0OmGUjaLGUAIAO8kePtWHzclZ1F2yvZXgn%2F7ceewPzqR%2FO"
                                      "LkfipJVCaOFHouuedHrUV0BbpQV2NxWfyHOoyvuyvgpf1cmJ%2"
                                      "BnX9fLvwA%3D&RelayState=aHR0cDovL3NwLmV4YW1wbGUuY2"
                                      "9tL2RlbW8xL21ldGFkYXRhLnBocA%3D%3D")}
                :body ""}
               (request/idp-logout-redirect-response
                {:issuer issuer
                 :user-email user-email
                 :idp-url idp-url
                 :relay-state (encode-decode/str->base64 issuer)
                 :request-id req-id}))))
      (testing "with signing"
        (is (= {:status 302
                :headers {"Cache-control" "no-cache, no-store"
                          "Pragma" "no-cache"
                          "location" (str
                                      "http://idp.example.com/SSOService.php?SAMLRequest="
                                      "nZHLTsMwEEV%2FJfK%2BycS0DbGaFKQAihRaiRQWbJBlT9pI8Y"
                                      "PYqfr5pA%2BkwoIFO4%2Bse88czWJ5UF2wx961RmckDoEEqIWR"
                                      "rd5m5HXzOLkly3zhuOosq8zWDP4FPwd0PhiD2rHTT0aGXjPDXe"
                                      "uY5god84LV988VoyEw2xtvhOlIUIy5VnN%2FYu28tyyKWmlDPH"
                                      "BlOwyFUVFdr2vs963A0O4sCcoiI%2BvVQ7V%2BKlcfMaQJJA3A"
                                      "DfCZBJhTEKlMZZMmzZwmvMFUCkGnY8y5AUvtPNc%2BIxQoTCCd"
                                      "0OmGUjaLGUAIAO8kePtWHzclZ1F2yvZXgn%2F7ceewPzqR%2FO"
                                      "LkfipJVCaOFHouuedHrUV0BbpQV2NxWfyHOoyvuyvgpf1cmJ%2"
                                      "BnX9fLvwA%3D&RelayState=aHR0cDovL3NwLmV4YW1wbGUuY2"
                                      "9tL2RlbW8xL21ldGFkYXRhLnBocA%3D%3D&SigAlg=http%3A%"
                                      "2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&S"
                                      "ignature=oChvLW5JXLhuCbD38uNk7EQv9D4TwQxfMKNKCmd1N"
                                      "RLE205H96kC1XBz%2BcTKN5Q1vqbEO%2Fg3u5esCSeEsElEkdd"
                                      "0PKkRq9M64RyzLJg70jeCyQYEVRjM9k6TatAX8ge4dWMieyiE7"
                                      "5yuOCGlASPZ1nck8cKxVtDTORLc6OaZ2vM%3D")}
                :body ""}
               (request/idp-logout-redirect-response
                {:issuer issuer
                 :credential test/sp-private-key
                 :user-email user-email
                 :idp-url idp-url
                 :relay-state (encode-decode/str->base64 issuer)
                 :request-id req-id})))))))
