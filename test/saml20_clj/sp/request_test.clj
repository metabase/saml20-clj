(ns saml20-clj.sp.request-test
  (:require [clojure.test :refer [deftest is testing]]
            [java-time.api :as t]
            [saml20-clj.encode-decode :as encode-decode]
            [saml20-clj.sp.request :as request]
            [saml20-clj.test :as test]))

(def target-uri "http://sp.example.com/demo1/index.php?acs")

(deftest idp-redirect-response-test
  (t/with-clock (t/mock-clock (t/instant "2020-09-24T22:51:00.000Z"))
    (testing "without signature"
      (let [request {:request-id "ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24"
                     :sp-name    "SP test"
                     :acs-url    "http://sp.example.com/demo1/index.php?acs"
                     :idp-url    "http://idp.example.com/SSOService.php"
                     :issuer     "http://sp.example.com/demo1/metadata.php"
                     :relay-state target-uri}]
        (is (= {:status 302,
                :body "",
                :headers
                {"Cache-control" "no-cache, no-store"
                 "Pragma" "no-cache"
                 "location" (str
                             "http://idp.example.com/SSOService.php?SAMLRequest="
                             "fVLLbtswEPwVgndJFPNwRFg2nLppDbi2YDk59FIw5KomIJEqlz"
                             "Lcv4%2BsKEFyiK%2B7OzuzMzudn5qaHMGjcTanacwoAaucNvZv"
                             "Th%2F3D9Ednc%2BmKJuat2LRhYPdwb8OMJAeaFG8dnLaeSucRI"
                             "PCygZQBCXKxa%2B14DETrXfBKVdTskAEH3qqb85i14AvwR%2BN"
                             "gsfdOqeHEFqRJNjGcJJNW0OsXJNoaFyaGKvhFLeHdi4VUrLsBR"
                             "grwyB6xBn9GViW23H7GUfJapnT7eb7evtjtflzx7IJm1SMXTF5"
                             "oxm75UxlOtNVNqlu%2BURWkGml%2BHUPw0IimiPktJI1wrmCHa"
                             "wsBmlDTjnjLGJZxK%2F3nIubVDAWM8Z%2BU1KMZ9%2F34gc7L3"
                             "n0%2FDqE4ud%2BX0Q70MaDCsOSo9HgNz0ip2VBQn86JU9vifVY"
                             "OuYjBmH%2BYzCXOeVbGnR2yfsGgtQyyLON0%2BQj1ftjnNWtlo"
                             "WrjfpPHpxvZPiaOo3ToWJ0VA2jorPYgjKVAU2T2cjx%2Bd1mLw"
                             "%3D%3D&RelayState=http%3A%2F%2Fsp.example.com%2Fde"
                             "mo1%2Findex.php%3Facs")}}
               (request/idp-redirect-response request)))))
    (testing "with a signature"
      (let [request {:request-id "ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24"
                     :sp-name    "SP test"
                     :acs-url    "http://sp.example.com/demo1/index.php?acs"
                     :idp-url    "http://idp.example.com/SSOService.php"
                     :issuer     "http://sp.example.com/demo1/metadata.php"
                     :credential test/sp-private-key
                     :relay-state target-uri}]
        (is (= {:status 302,
                :body "",
                :headers
                {"Cache-control" "no-cache, no-store"
                 "Pragma" "no-cache"
                 "location" (str
                             "http://idp.example.com/SSOService.php?SAMLRequest="
                             "fVLLbtswEPwVgndJFPNwRFg2nLppDbi2YDk59FIw5KomIJEqlz"
                             "Lcv4%2BsKEFyiK%2B7OzuzMzudn5qaHMGjcTanacwoAaucNvZv"
                             "Th%2F3D9Ednc%2BmKJuat2LRhYPdwb8OMJAeaFG8dnLaeSucRI"
                             "PCygZQBCXKxa%2B14DETrXfBKVdTskAEH3qqb85i14AvwR%2BN"
                             "gsfdOqeHEFqRJNjGcJJNW0OsXJNoaFyaGKvhFLeHdi4VUrLsBR"
                             "grwyB6xBn9GViW23H7GUfJapnT7eb7evtjtflzx7IJm1SMXTF5"
                             "oxm75UxlOtNVNqlu%2BURWkGml%2BHUPw0IimiPktJI1wrmCHa"
                             "wsBmlDTjnjLGJZxK%2F3nIubVDAWM8Z%2BU1KMZ9%2F34gc7L3"
                             "n0%2FDqE4ud%2BX0Q70MaDCsOSo9HgNz0ip2VBQn86JU9vifVY"
                             "OuYjBmH%2BYzCXOeVbGnR2yfsGgtQyyLON0%2BQj1ftjnNWtlo"
                             "WrjfpPHpxvZPiaOo3ToWJ0VA2jorPYgjKVAU2T2cjx%2Bd1mLw"
                             "%3D%3D&RelayState=http%3A%2F%2Fsp.example.com%2Fde"
                             "mo1%2Findex.php%3Facs&SigAlg=http%3A%2F%2Fwww.w3.o"
                             "rg%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=KJSj"
                             "oD6Mg7OH%2F2pCd6qEDmqSxqWZqOmBePLC5RemNjmLE2ElfnO0"
                             "tPvTgWDbY7Io5ENEElvsa8eJziZz3TYtFJa1AUDtO2c6BQX627"
                             "LA7Y0gCvhj035rxJZPPh8ucdTCjNA0roYFpdlQiKQZnUJmJgX2"
                             "QvB9Zr7WTIEPXMNkb%2B0%3D")}}
               (request/idp-redirect-response request)))))))

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
                                      "nZFNS8NAEIb%2FSth7k8naNmZpUoWqBGoLTfXgRZbdSRvIfpjd"
                                      "lP580y%2BIHjx4m2F455mHmc2PqgkO2Lra6IzEIZAAtTCy1ruM"
                                      "vG2fR%2Fdkns8cVw21bGl2pvMb%2FOrQ%2BaBPascuo4x0rWaG"
                                      "u9oxzRU65gUrH1%2BXjIbAbGu8EaYhwaIP1pr7M23vvWVRVEsb"
                                      "4pEr22AojIrKcl1ie6gFhnZvSVAsMrJePS3XL8XqM4Y0gaQCuA"
                                      "M%2BkQBTCiKVqazSpJrShFeYSiHouI8512GhnefaZ4QChRGkIz"
                                      "reUsomMQMIAeCDBO83%2Bf5SclVl53A7VPzbkDuH7cmK5Fcr91"
                                      "NKojJxpNBzyT0%2Fic2iIeoGXvWri8W%2FwF1fPQyYN8BlZX5t"
                                      "f30x%2FwY%3D&RelayState=aHR0cDovL3NwLmV4YW1wbGUuY2"
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
                                      "nZFNS8NAEIb%2FSth7k8naNmZpUoWqBGoLTfXgRZbdSRvIfpjd"
                                      "lP580y%2BIHjx4m2F455mHmc2PqgkO2Lra6IzEIZAAtTCy1ruM"
                                      "vG2fR%2Fdkns8cVw21bGl2pvMb%2FOrQ%2BaBPascuo4x0rWaG"
                                      "u9oxzRU65gUrH1%2BXjIbAbGu8EaYhwaIP1pr7M23vvWVRVEsb"
                                      "4pEr22AojIrKcl1ie6gFhnZvSVAsMrJePS3XL8XqM4Y0gaQCuA"
                                      "M%2BkQBTCiKVqazSpJrShFeYSiHouI8512GhnefaZ4QChRGkIz"
                                      "reUsomMQMIAeCDBO83%2Bf5SclVl53A7VPzbkDuH7cmK5Fcr91"
                                      "NKojJxpNBzyT0%2Fic2iIeoGXvWri8W%2FwF1fPQyYN8BlZX5t"
                                      "f30x%2FwY%3D&RelayState=aHR0cDovL3NwLmV4YW1wbGUuY2"
                                      "9tL2RlbW8xL21ldGFkYXRhLnBocA%3D%3D&SigAlg=http%3A%"
                                      "2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&S"
                                      "ignature=N1dSZcA1AO6Et3%2BHgYNlyvAGnPuflVWyCerVrES"
                                      "jMLNCt%2F%2BshuUkwI%2BkyHsffbRS0iO0lh1bkIcexOFU8ja"
                                      "%2B3t5YcWsr%2B3AkfUeeNOoReeogKh2qIcU9UaHU7tkUj4SQi"
                                      "B%2BnWqfpueLkI8WaSE2hVBCe0qwiLLY4hvkEI2%2Fz5BI%3D")}
                :body ""}
               (request/idp-logout-redirect-response
                {:issuer issuer
                 :credential test/sp-private-key
                 :user-email user-email
                 :idp-url idp-url
                 :relay-state (encode-decode/str->base64 issuer)
                 :request-id req-id})))))))
