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
  (is (= {:status  302
          :headers {"Location" (str "https://idp.example.com"
                                    "?SAMLRequest=C3b09VEIcg0MdQ0OUXD3dw1W8HANcgUA"
                                    "&RelayState=http%3A%2F%2Fsp.example.com%2Fdemo1%2Findex.php%3Facs")}
          :body    ""}
         (request/idp-redirect-response "SAML REQUEST GOES HERE"
                                        test/idp-uri
                                        target-uri)))
  (testing "Should handle URIs that already have query params in them"
    (is (= {:status  302
            :headers {"Location" (str "https://idp.example.com"
                                      "?x=100"
                                      "&SAMLRequest=C3b09VEIcg0MdQ0OUXD3dw1W8HANcgUA"
                                      "&RelayState=http%3A%2F%2Fsp.example.com%2Fdemo1%2Findex.php%3Facs")}
            :body    ""}
           (request/idp-redirect-response "SAML REQUEST GOES HERE"
                                          (str test/idp-uri "?x=100")
                                          target-uri)))))

(deftest request-test
  (is (= [(str "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
               "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
               " AssertionConsumerServiceURL=\"http://sp.example.com/demo1/index.php?acs\""
               " Destination=\"http://idp.example.com/SSOService.php\""
               " ID=\"ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24\""
               " IssueInstant=\"2020-09-24T22:51:00Z\""
               " ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""
               " ProviderName=\"SP test\""
               " Version=\"2.0\">")
          "  <saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">http://sp.example.com/demo1/metadata.php</saml:Issuer>"
          "</samlp:AuthnRequest>"]
         (str/split-lines
          (coerce/->xml-string
           (t/with-clock (t/mock-clock (t/instant "2020-09-24T22:51:00.000Z"))
             (request/request
              {:request-id "ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24"
               :sp-name    "SP test"
               :acs-url    "http://sp.example.com/demo1/index.php?acs"
               :idp-url    "http://idp.example.com/SSOService.php"
               :issuer     "http://sp.example.com/demo1/metadata.php"}))))))

  (testing "should be able to create a signed request"
    (is (= [(str "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                 "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
                 " AssertionConsumerServiceURL=\"http://sp.example.com/demo1/index.php?acs\""
                 " Destination=\"http://idp.example.com/SSOService.php\""
                 " ID=\"ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24\""
                 " IssueInstant=\"2020-09-24T22:51:00.000Z\""
                 " ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""
                 " ProviderName=\"SP test\""
                 " Version=\"2.0\">")
            "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">http://sp.example.com/demo1/metadata.php</saml:Issuer>"
            "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
            "<ds:SignedInfo>"
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
            "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>"
            "<ds:Reference URI=\"#ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24\">"
            "<ds:Transforms>"
            "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"
            "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
            "</ds:Transforms>"
            "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
            "<ds:DigestValue>rQl/YQbJmHraUcOQLXjT9OvihbrpTVyKCA835MDcrdc=</ds:DigestValue>"
            "</ds:Reference>"
            "</ds:SignedInfo>"
            "<ds:SignatureValue>"
            "TJ5uCyLq6bs5f7+NIYoOXcHts1h3VjMSEVvgiPZqOz2fvWiZZFSsMLODUJ6ZokcSll8lxkkXrJcO&#13;"
            "ttPk2QsWzO7LBd3RCVVVIUuCBvu52tVKjvA6Ol2DGRPAA7wgoUB95JWQdrt/HKVEBHFHxVHa+MNc&#13;"
            "YkhGaFj38LZ+vcCyg1c="
            "</ds:SignatureValue>"
            "</ds:Signature>"
            "</samlp:AuthnRequest>"]
           (->> (t/with-clock (t/mock-clock (t/instant "2020-09-24T22:51:00.000Z"))
                  (request/request
                   {:request-id "ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24"
                    :sp-name    "SP test"
                    :acs-url    "http://sp.example.com/demo1/index.php?acs"
                    :idp-url    "http://idp.example.com/SSOService.php"
                    :issuer     "http://sp.example.com/demo1/metadata.php"
                    :credential test/sp-private-key}))
                coerce/->xml-string
                str/split-lines
                ;; for some reason it indents the XML differently on the REPL and in the tests
                (map str/trim)
                (filter seq)))))

  (testing "should be able to create a signed request (with KeyInfo)"
    (is (= [(str "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                 "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
                 " AssertionConsumerServiceURL=\"http://sp.example.com/demo1/index.php?acs\""
                 " Destination=\"http://idp.example.com/SSOService.php\""
                 " ID=\"ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24\""
                 " IssueInstant=\"2020-09-24T22:51:00.000Z\""
                 " ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""
                 " ProviderName=\"SP test\""
                 " Version=\"2.0\">")
            "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">http://sp.example.com/demo1/metadata.php</saml:Issuer>"
            "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
            "<ds:SignedInfo>"
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
            "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>"
            "<ds:Reference URI=\"#ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24\">"
            "<ds:Transforms>"
            "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"
            "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
            "</ds:Transforms>"
            "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"
            "<ds:DigestValue>rQl/YQbJmHraUcOQLXjT9OvihbrpTVyKCA835MDcrdc=</ds:DigestValue>"
            "</ds:Reference>"
            "</ds:SignedInfo>"
            "<ds:SignatureValue>"
            "TJ5uCyLq6bs5f7+NIYoOXcHts1h3VjMSEVvgiPZqOz2fvWiZZFSsMLODUJ6ZokcSll8lxkkXrJcO&#13;"
            "ttPk2QsWzO7LBd3RCVVVIUuCBvu52tVKjvA6Ol2DGRPAA7wgoUB95JWQdrt/HKVEBHFHxVHa+MNc&#13;"
            "YkhGaFj38LZ+vcCyg1c="
            "</ds:SignatureValue>"
            "<ds:KeyInfo>"
            "<ds:X509Data>"
            "<ds:X509Certificate>MIICZjCCAc+gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBQMQswCQYDVQQGEwJ1czETMBEGA1UECAwK"
            "Q2FsaWZvcm5pYTETMBEGA1UECgwKRXhhbXBsZSBTUDEXMBUGA1UEAwwOc3AuZXhhbXBsZS5jb20w"
            "HhcNMjAwOTIzMTc0MzA2WhcNMzAwOTIxMTc0MzA2WjBQMQswCQYDVQQGEwJ1czETMBEGA1UECAwK"
            "Q2FsaWZvcm5pYTETMBEGA1UECgwKRXhhbXBsZSBTUDEXMBUGA1UEAwwOc3AuZXhhbXBsZS5jb20w"
            "gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMCOR6lM1raadHr3MnDU7ydGHUmMhZ5ZImwSHcxY"
            "rY6/F3TW+S6CPMuAfHJsNQZ57nG4wUhNCbfXdumfVxzoPMzD7oivKKVxeMK6HaUuGsGg9OK4ON++"
            "EVxomWdmPyJdHpiUaGveGU0BQgzI7aqNibncPYPxJgK9DZEIfDjp05lDAgMBAAGjUDBOMB0GA1Ud"
            "DgQWBBStKfCHxILkLbv2tAEK54+Wn/xF+zAfBgNVHSMEGDAWgBStKfCHxILkLbv2tAEK54+Wn/xF"
            "+zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAIRA7mJdPPmTWc3wsPLDv+nMeR0nr5a6"
            "r8dZU5lOTqGfC43YvJ1NEysO3AB6YuiG1KKXERxtlISyYvU9wNrna2IPDU0njcU/a3dEBqa32lD3"
            "GxfUvbpzIcZovBYqQ7Jhfa86GvNKxRoyUEExVqyHh6i44S4NCJvr8IdnRilYBksl</ds:X509Certificate>"
            "</ds:X509Data>"
            "</ds:KeyInfo>"
            "</ds:Signature>"
            "</samlp:AuthnRequest>"]
           (->> (t/with-clock (t/mock-clock (t/instant "2020-09-24T22:51:00.000Z"))
                  (request/request
                   {:request-id  "ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24"
                    :sp-name     "SP test"
                    :acs-url     "http://sp.example.com/demo1/index.php?acs"
                    :idp-url     "http://idp.example.com/SSOService.php"
                    :issuer      "http://sp.example.com/demo1/metadata.php"
                    :credential  [test/sp-cert test/sp-private-key]}))
                coerce/->xml-string
                str/split-lines
                ;; for some reason it indents the XML differently on the REPL and in the tests
                (map str/trim)
                (filter seq))))))

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
                  " IssueInstant=\"2020-09-29T20:12:00Z\""
                  " ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""
                  " ProviderName=\"My Example SP\""
                  " Version=\"2.0\">"
                  "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
                  "http://sp.example.com/demo1/metadata.php"
                  "</saml:Issuer>"
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
              (is (thrown-with-msg?
                   java.lang.AssertionError
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
            {:xmlns:samlp "urn:oasis:names:tc:SAML:2.0:protocol"
             :xmlns:saml "urn:oasis:names:tc:SAML:2.0:assertion"
             :Version "2.0"
             :ID "ONELOGIN_109707f0030a5d00620c9d9df97f627afe9dcc24"
             :IssueInstant "2020-09-24T22:51:00Z"
             :Destination "http://idp.example.com/SSOService.php"}
            [:saml:Issuer "http://sp.example.com/demo1/metadata.php"]
            [:saml:NameID {:Format "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"} "user@example.com"]
            [:samlp:SessionIndex "SessionIndex_From_Authentication_Assertion"]]
           logout-xml))
    (is (= (str "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" "\n"
                "<samlp:LogoutRequest Destination=\"http://idp.example.com/SSOService.php\" "
                "ID=\"ONELOGIN_109707f0030a5d00620c9d9df97f627afe9dcc24\" "
                "IssueInstant=\"2020-09-24T22:51:00Z\" "
                "Version=\"2.0\" "
                "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" "
                "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
                "<saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>"
                "<saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress\">user@example.com</saml:NameID>"
                "<samlp:SessionIndex>SessionIndex_From_Authentication_Assertion</samlp:SessionIndex>"
                "</samlp:LogoutRequest>")
           (coerce/->xml-string logout-xml)))))

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
