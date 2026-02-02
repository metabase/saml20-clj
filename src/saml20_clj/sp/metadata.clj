(ns saml20-clj.sp.metadata
  (:require [clojure.string :as str]
            [saml20-clj
             [coerce :as coerce]
             [encode-decode :as encode]]))

(defn metadata [{:keys [app-name acs-url slo-url
                        sp-cert                            ; legacy - for backward compatibility
                        sp-encryption-cert sp-signing-cert
                        requests-signed
                        want-assertions-signed]
                 :or {want-assertions-signed true
                      requests-signed true}}]
  (let [signing-cert (or sp-signing-cert sp-cert)
        encryption-cert (or sp-encryption-cert sp-cert)
        encoded-signing-cert (some-> ^java.security.cert.X509Certificate signing-cert
                                     .getEncoded
                                     encode/encode-base64
                                     encode/bytes->str)
        encoded-encryption-cert (some-> ^java.security.cert.X509Certificate encryption-cert
                                        .getEncoded
                                        encode/encode-base64
                                        encode/bytes->str)]
    (coerce/->xml-string
     [:md:EntityDescriptor {:xmlns:md "urn:oasis:names:tc:SAML:2.0:metadata"
                            :ID       (str/replace acs-url #"[:/]" "_")
                            :entityID app-name}
      [:md:SPSSODescriptor {:AuthnRequestsSigned        (str requests-signed)
                            :WantAssertionsSigned       (str want-assertions-signed)
                            :protocolSupportEnumeration "urn:oasis:names:tc:SAML:2.0:protocol"}
       (when encoded-signing-cert
         [:md:KeyDescriptor  {:use "signing"}
          [:ds:KeyInfo  {:xmlns:ds "http://www.w3.org/2000/09/xmldsig#"}
           [:ds:X509Data
            [:ds:X509Certificate encoded-signing-cert]]]])
       (when encoded-encryption-cert
         [:md:KeyDescriptor  {:use "encryption"}
          [:ds:KeyInfo  {:xmlns:ds "http://www.w3.org/2000/09/xmldsig#"}
           [:ds:X509Data
            [:ds:X509Certificate encoded-encryption-cert]]]])
       (when slo-url
         [:md:SingleLogoutService {:Binding "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                   :Location slo-url}])
       [:md:NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"]
       [:md:NameIDFormat "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"]
       [:md:NameIDFormat "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"]
       [:md:NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"]
       [:md:NameIDFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"]
       [:md:AssertionConsumerService {:Binding   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                      :Location  acs-url
                                      :index     "0"
                                      :isDefault "true"}]]])))
