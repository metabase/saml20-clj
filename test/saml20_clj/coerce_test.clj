(ns saml20-clj.coerce-test
  (:require [clojure.test :refer :all]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.test :as test]))

(defn- key-fingerprint [^java.security.Key k]
  (when k
    (org.apache.commons.codec.digest.DigestUtils/md5Hex (.getEncoded k))))

(deftest ->PrivateKey-test
  (is (= nil (coerce/->PrivateKey nil)))
  (letfn [(is-key-with-fingerprint? [input]
            (let [k (coerce/->PrivateKey input)]
              (is (instance? java.security.PrivateKey k))
              (is (= "af284d1f7bfa789c787f689a95604d31"
                     (key-fingerprint k)))))]
    (testing "Should be able to get a private key from base-64-encoded string"
      (is-key-with-fingerprint? test/sp-private-key))
    (testing "Should be able to get a private key from a Java keystore"
      (is-key-with-fingerprint? {:filename test/keystore-filename
                                 :password test/keystore-password
                                 :alias "sp"}))
    (testing "Should be able to get a private key from X509Credential"
      (is-key-with-fingerprint? (coerce/->Credential test/sp-cert test/sp-private-key)))))

(def ^:private test-certificate-str-1
  "MIIDsjCCApqgAwIBAgIGAWtM1OOxMA0GCSqGSIb3DQEBCwUAMIGZMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxGjAYBgNVBAMMEW1ldGFiYXNlLXZpY3RvcmlhMRwwGgYJKoZI
hvcNAQkBFg1pbmZvQG9rdGEuY29tMB4XDTE5MDYxMjE3NTQ0OFoXDTI5MDYxMjE3NTU0OFowgZkx
CzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2Nv
MQ0wCwYDVQQKDARPa3RhMRQwEgYDVQQLDAtTU09Qcm92aWRlcjEaMBgGA1UEAwwRbWV0YWJhc2Ut
dmljdG9yaWExHDAaBgkqhkiG9w0BCQEWDWluZm9Ab2t0YS5jb20wggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQCJNDIHd05aBXALoQStEvErsnJZDx1PIHTYGDY30SGHad8vXANg+tpThny3
ZMmGx8j3tDDwjsijPa8SQtL8I8GrTKO1h2zqM+3sKrgyLk6fcXnKWBqbFx9gpqz9bRxT76WKYTxV
3t71GtVb8fSfns1fv3u3thsUADDcJmOK65snwirtahie61IDIvoRxMIInu26kw1gCFtOcidoY0yL
RhGgaMjgGYOd2auW5A7bQV9kxePLg8o8rU+KXhTbuHJg0dgW8gVNAv5IKEQQ1VZNTjALR+N6Mca1
p0tuofEVggkA7x9t0O+xWXxUrbSs9C1DxKkxF4xI0z8M/ocqdtwPxNP5AgMBAAEwDQYJKoZIhvcN
AQELBQADggEBAIO5cVa/P50nXuXaMK/klblZ+1MFbJ8Ti86TSPcdnxYO8nbWwQuUwKKuRHf6y5li
7ctaeXhMfyx/rGsYH4TDgzZhpZmGgZmAKGohDH4YxHctqyxNpRPwJe2kIkJN5yEqLUPNwqm2I7Dw
PcmkewOYEf71Y/sBF0/vRJev5n3upo2nW9RzUz9ptAtWn7EoLsN+grcohJpygj7jiJmbicxblNqF
uvuZkzz+X+qt2W/1mbVDyuIwsvUQOeRbpM+xv11dxheLRKt3kB8Gf6kqd8EjBtHmMFL8s4fdHyfM
eRzAWU6exmsx49oEvw5LrBSTJ97ekvVFfrEASyd96sgeV2Nl0No=")

(def ^:private test-certificate-str-2
  "-----BEGIN CERTIFICATE-----
MIICEjCCAXsCAg36MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
ODIyMDUyNjU0WhcNMTcwODIxMDUyNjU0WjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAm/xmkHmEQrurE/0re/jeFRLl
8ZPjBop7uLHhnia7lQG/5zDtZIUC3RVpqDSwBuw/NTweGyuP+o8AG98HxqxTBwID
AQABMA0GCSqGSIb3DQEBBQUAA4GBABS2TLuBeTPmcaTaUW/LCB2NYOy8GMdzR1mx
8iBIu2H6/E2tiY3RIevV2OW61qY2/XRQg7YPxx3ffeUugX9F4J/iPnnu1zAxxyBy
2VguKv4SWjRFoRkIfIlHX0qVviMhSlNy2ioFLy7JcPZb+v3ftDGywUqcBiVDoea0
Hn+GmxZA
-----END CERTIFICATE-----")

(def ^:private test-certificate-str-3
  "-----BEGIN CERTIFICATE-----
MIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
ODIyMDUyNzQxWhcNMTcwODIxMDUyNzQxWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0z9FeMynsC8+u
dvX+LciZxnh5uRj4C9S6tNeeAlIGCfQYk0zUcNFCoCkTknNQd/YEiawDLNbxBqut
bMDZ1aarys1a0lYmUeVLCIqvzBkPJTSQsCopQQ9V8WuT252zzNzs68dVGNdCJd5J
NRQykpwexmnjPPv0mvj7i8XgG379TyW6P+WWV5okeUkXJ9eJS2ouDYdR2SM9BoVW
+FgxDu6BmXhozW5EfsnajFp7HL8kQClI0QOc79yuKl3492rH6bzFsFn2lfwWy9ic
7cP8EpCTeFp1tFaD+vxBhPZkeTQ1HKx6hQ5zeHIB5ySJJZ7af2W8r4eTGYzbdRW2
4DDHCPhZAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAQMv+BFvGdMVzkQaQ3/+2noVz
/uAKbzpEL8xTcxYyP3lkOeh4FoxiSWqy5pGFALdPONoDuYFpLhjJSZaEwuvjI/Tr
rGhLV1pRG9frwDFshqD2Vaj4ENBCBh6UpeBop5+285zQ4SI7q4U9oSebUDJiuOx6
+tZ9KynmrbJpTSi0+BM=
-----END CERTIFICATE-----")

(def ^:private test-certificate-str-4
  "-----BEGIN CERTIFICATE-----
MIID2jCCA0MCAg39MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
ODIyMDUyODAwWhcNMTcwODIxMDUyODAwWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCwvWITOLeyTbS1
Q/UacqeILIK16UHLvSymIlbbiT7mpD4SMwB343xpIlXN64fC0Y1ylT6LLeX4St7A
cJrGIV3AMmJcsDsNzgo577LqtNvnOkLH0GojisFEKQiREX6gOgq9tWSqwaENccTE
sAXuV6AQ1ST+G16s00iN92hjX9V/V66snRwTsJ/p4WRpLSdAj4272hiM19qIg9zr
h92e2rQy7E/UShW4gpOrhg2f6fcCBm+aXIga+qxaSLchcDUvPXrpIxTd/OWQ23Qh
vIEzkGbPlBA8J7Nw9KCyaxbYMBFb1i0lBjwKLjmcoihiI7PVthAOu/B71D2hKcFj
Kpfv4D1Uam/0VumKwhwuhZVNjLq1BR1FKRJ1CioLG4wCTr0LVgtvvUyhFrS+3PdU
R0T5HlAQWPMyQDHgCpbOHW0wc0hbuNeO/lS82LjieGNFxKmMBFF9lsN2zsA6Qw32
Xkb2/EFltXCtpuOwVztdk4MDrnaDXy9zMZuqFHpv5lWTbDVwDdyEQNclYlbAEbDe
vEQo/rAOZFl94Mu63rAgLiPeZN4IdS/48or5KaQaCOe0DuAb4GWNIQ42cYQ5TsEH
Wt+FIOAMSpf9hNPjDeu1uff40DOtsiyGeX9NViqKtttaHpvd7rb2zsasbcAGUl+f
NQJj4qImPSB9ThqZqPTukEcM/NtbeQIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAIAi
gU3My8kYYniDuKEXSJmbVB+K1upHxWDA8R6KMZGXfbe5BRd8s40cY6JBYL52Tgqd
l8z5Ek8dC4NNpfpcZc/teT1WqiO2wnpGHjgMDuDL1mxCZNL422jHpiPWkWp3AuDI
c7tL1QjbfAUHAQYwmHkWgPP+T2wAv0pOt36GgMCM
-----END CERTIFICATE-----")

(deftest ->X509Certificate-test
  (testing "from String"
    (testing "make sure we can parse a certificate, no armor"
      (coerce/->X509Certificate test-certificate-str-1)
      (is (instance? java.security.cert.X509Certificate
                     (coerce/->X509Certificate test-certificate-str-1))))
    (testing "make sure we can parse a certificate with armor 512b key"
      (is (instance? java.security.cert.X509Certificate
                     (coerce/->X509Certificate test-certificate-str-2))))
    (testing "make sure we can parse a certificate with armor 2048b key"
      (is (instance? java.security.cert.X509Certificate
                     (coerce/->X509Certificate test-certificate-str-3))))
    (testing "make sure we can parse a certificate with armor 4096b key"
      (is (instance? java.security.cert.X509Certificate
                     (coerce/->X509Certificate test-certificate-str-4))))))

(defn- x509-credential-fingerprints [^org.opensaml.security.x509.X509Credential credential]
  {:public  (key-fingerprint (.getPublicKey credential))
   :private (key-fingerprint (.getPrivateKey credential))})

(deftest ->Credential-test
  (let [sp-fingerprints  {:public  "6e104aaa6daccb9c8f2b4d692441f3a5"
                          :private "af284d1f7bfa789c787f689a95604d31"}
        idp-fingerprints {:public "b2648dc4aa28760eaf33c789d58ba262", :private nil}]
    (testing "Should be able to get an X509Credential from Strings"
      (is (= sp-fingerprints
             (x509-credential-fingerprints (coerce/->Credential test/sp-cert test/sp-private-key)))))
    (testing "Should accept a tuple of [public-key private-key]"
      (is (= sp-fingerprints
             (x509-credential-fingerprints (coerce/->Credential [test/sp-cert test/sp-private-key]))))
      (is (= idp-fingerprints
             (x509-credential-fingerprints (coerce/->Credential [test/idp-cert])))))
    (testing "Should be able to get X509Credential from a keystore"
      (testing "public only"
        (is (= idp-fingerprints
               (x509-credential-fingerprints (coerce/->Credential {:filename test/keystore-filename
                                                                       :password test/keystore-password
                                                                       :alias    "idp"})))))
      (testing "public + private"
        (is (= sp-fingerprints
               (x509-credential-fingerprints (coerce/->Credential {:filename test/keystore-filename
                                                                       :password test/keystore-password
                                                                       :alias    "sp"}))))))))
