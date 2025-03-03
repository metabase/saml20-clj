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

(deftest ->LogoutResponse
  (let [logout-response-ring {:params {:SAMLResponse "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOkxvZ291dFJlc3BvbnNlIERlc3RpbmF0aW9uPSJodHRwOi8vbG9jYWxob3N0OjMwMDAvYXV0aC9zc28vaGFuZGxlX3NsbyIgSUQ9ImlkODYyMTQxMDMzODM0ODEzMDA4NTY4NzAiIEluUmVzcG9uc2VUbz0iaWQ2NjFiYWM5ZC0xYWMyLTQxNjctOTY0Ni05ZjEyMmY3ODhkMmYiIElzc3VlSW5zdGFudD0iMjAyNS0wMi0yNFQxNzoxOTo1Ny42MTBaIiBWZXJzaW9uPSIyLjAiIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIj48c2FtbDI6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5IiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+aHR0cDovL3d3dy5va3RhLmNvbS9leGtuZnpoMXA1TlhBTm96MTVkNzwvc2FtbDI6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48ZHM6UmVmZXJlbmNlIFVSST0iI2lkODYyMTQxMDMzODM0ODEzMDA4NTY4NzAiPjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT5yeGt3RVJSRkNVVklyTXdBZDBoMnJ3bE5PeDVaK1UvZzZiWkUrVHpSVlNVPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5jeXdMRW5kdVF6b3VSa3k4K2hNVXkrMUtBVS9Xb2pRcDJDcTZmMmVrNlFyM2hvbGYvcUt6dkpjNVBOTzBSSjh3UTdvdVlGYmR4V0s0Q0VobzQ0Qy9sOTJSZTl6V3djcXdUWjA5WWdKRFNYUjU2NXRsT2VjQ2pqNS9kd05hRUkrNUEzdGVIbC9GMk5qMDdrUGRtSThhWlMyQ2tJOTk4aXoxclV4bVRqSTJIQm9td3QxZ04vQ1NaNys4d2lWZkRmOGVycmZ0SFhGUmhkMzdRTzBob0NmeVlUY2R0b0RGQitTZmxsSCtpRHVyeE8vV2NkMTZoUEJRQ0Z6bW9tdHAwZHkxMW80NlZmMVFwNUlhMEt4allKOU1tNmxkVUE2dHVYUW40aTYzZXI0MkVNZjAzRTFDYUZrZlowRXROU2ZmY1A3UUhZeTk0OHpIcG1vcEprU3UwV0NsNVE9PTwvZHM6U2lnbmF0dXJlVmFsdWU+PGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRHFEQ0NBcENnQXdJQkFnSUdBWlVhd0VSWE1BMEdDU3FHU0liM0RRRUJDd1VBTUlHVU1Rc3dDUVlEVlFRR0V3SlZVekVUTUJFRwpBMVVFQ0F3S1EyRnNhV1p2Y201cFlURVdNQlFHQTFVRUJ3d05VMkZ1SUVaeVlXNWphWE5qYnpFTk1Bc0dBMVVFQ2d3RVQydDBZVEVVCk1CSUdBMVVFQ3d3TFUxTlBVSEp2ZG1sa1pYSXhGVEFUQmdOVkJBTU1ER1JsZGkwd09EVTBPREl5TlRFY01Cb0dDU3FHU0liM0RRRUoKQVJZTmFXNW1iMEJ2YTNSaExtTnZiVEFlRncweU5UQXlNVGd5TURJNE1qSmFGdzB6TlRBeU1UZ3lNREk1TWpKYU1JR1VNUXN3Q1FZRApWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tRMkZzYVdadmNtNXBZVEVXTUJRR0ExVUVCd3dOVTJGdUlFWnlZVzVqYVhOamJ6RU5NQXNHCkExVUVDZ3dFVDJ0MFlURVVNQklHQTFVRUN3d0xVMU5QVUhKdmRtbGtaWEl4RlRBVEJnTlZCQU1NREdSbGRpMHdPRFUwT0RJeU5URWMKTUJvR0NTcUdTSWIzRFFFSkFSWU5hVzVtYjBCdmEzUmhMbU52YlRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQwpnZ0VCQU8zbkhxZUMraXRINmdyUytvSEdMMEVvNXZUR2EycWQ5VzFyWkplcW1BcWJwZXk0WnY2c0VhSEVqL1FJTEVVbGVNOEl5YTJvClErdkxiWTFJU05Fb0R2TCt1MmZDM0NGWjE1VlRnb0hmdEhZOFF5K21vdW1pWjZyQWU2MzdSY1BQT0RmRXlSUzRhY2FZa29TQ0g1UDQKbEtkVnVOQTc2UXN6KzQrelNnbGNmMURmT0JhQ3FuRHJWWXUrbGVaTWxSSVJaL3ZZRW8zT012ejZXTGJnUy9KMXAra2xkZDJGanpFdQp5ZzdRYiszOGZCZ3pkREhSYmZUeGQzRVptTThFblpxQ0tIWklna3ZVZXBaWUp3TlVXM3FVR3dlR0Y0c0JQaWNnQnI2RU0rR2RJeWVmCnFZNzlEV2h4RVhIOEdhMzA2Yzk4L29KajBiUHBlRFVwb001OWZEN3QyekVDQXdFQUFUQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUEKQ3VmRnN5NHNGSkhvNk5XMFpSUy9RT0lFWTFVYjNZNGlHQytIM0tXemdsRDJqNTA1N0tqb3U1ZDNvSmIwSDB0OEpJK0tLOUhIMGk5YwpkRldyQXQ2OTZ1MFpmUEk2TVNWV2x5bVQ5WWY4ZkV1VW9xTmlqQ0RtcW96TlhINUpLQUM2TVZTNzdWZXY0amMxdHJFQmVxd0o5ZE5YCnpFMXBCUDh4YnpWSzBET0NQRW5EL0p4eHQyWmR4d1hiZjlCOWUyeGRTNWYrUG8vZjdCbDkrTVoxeWUyR1ZGV1J0cEJmZzUwU2pFdWYKMThMT2NsRjdibGhZZ1g0SnA4TFJVaGp4cVdUb0Qxc1B3QUxwTmw5SkJ5bGJNb2w2QUlLNkxURG8rMitScUNlQzdjU0FZcjY3SXY0cwppQ0RpbU9DMWlkR01vcU1QT1pOTXBmYXZUemxNeFptalAxQmhiUT09PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PHNhbWwycDpTdGF0dXMgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxzYW1sMnA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+PC9zYW1sMnA6U3RhdHVzPjwvc2FtbDJwOkxvZ291dFJlc3BvbnNlPg=="
                                       :RelayState "aHR0cDovL2xvY2FsaG9zdDozMDAwL2F1dGgvc3NvL2hhbmRsZV9zbG8="}
                              :content-type "application/x-www-form-urlencoded"
                              :request-method :post}]
    (testing "converts ring response into logout response object"
      (is (instance? org.opensaml.saml.saml2.core.LogoutResponse
                     (coerce/->LogoutResponse logout-response-ring))))))
