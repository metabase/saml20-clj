(ns saml20-clj.sp.metadata
  (:require [clojure.string :as str]
            [saml20-clj.coerce :as coerce])
  (:import [org.opensaml.saml.saml2.metadata.impl AssertionConsumerServiceBuilder EntityDescriptorBuilder KeyDescriptorBuilder NameIDFormatBuilder SingleLogoutServiceBuilder SPSSODescriptorBuilder]
           org.opensaml.core.xml.util.XMLObjectSupport
           org.opensaml.saml.common.xml.SAMLConstants
           org.opensaml.saml.saml2.core.NameIDType
           org.opensaml.security.credential.UsageType
           org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory))

(set! *warn-on-reflection* true)

(def ^:private name-id-formats
  [NameIDType/EMAIL NameIDType/TRANSIENT NameIDType/PERSISTENT NameIDType/UNSPECIFIED NameIDType/X509_SUBJECT])

(def ^:private cert-uses
  [UsageType/SIGNING UsageType/ENCRYPTION])

(defn metadata
  "Return string-encoded XML of this SAML SP's metadata."
  [{:keys [app-name acs-url slo-url sp-cert
           ^Boolean requests-signed
           ^Boolean want-assertions-signed]
    :or {want-assertions-signed true
         requests-signed true}}]
  (let [entity-descriptor (doto (.buildObject (EntityDescriptorBuilder.))
                            (.setID (str/replace acs-url #"[:/]" "_"))
                            (.setEntityID app-name))
        sp-sso-descriptor (doto (.buildObject (SPSSODescriptorBuilder.))
                            (.setAuthnRequestsSigned requests-signed)
                            (.setWantAssertionsSigned want-assertions-signed)
                            (.addSupportedProtocol SAMLConstants/SAML20P_NS))]

    (.. sp-sso-descriptor
        (getAssertionConsumerServices)
        (add (doto (.buildObject (AssertionConsumerServiceBuilder.))
               (.setIndex (Integer. 0))
               (.setIsDefault true)
               (.setLocation acs-url)
               (.setBinding SAMLConstants/SAML2_POST_BINDING_URI))))
    (doseq [name-id-format name-id-formats]
      (.. sp-sso-descriptor
          (getNameIDFormats)
          (add (doto (.buildObject (NameIDFormatBuilder.))
                 (.setURI name-id-format)))))
    (when sp-cert
      (let [key-info-generator (.newInstance (doto (X509KeyInfoGeneratorFactory.)
                                               (.setEmitEntityCertificate true)))]
        (doseq [cert-use cert-uses]
          (.. sp-sso-descriptor
              (getKeyDescriptors)
              (add (doto (.buildObject (KeyDescriptorBuilder.))
                     (.setUse cert-use)
                     (.setKeyInfo (.generate key-info-generator sp-cert))))))))
    (when slo-url
      (.. sp-sso-descriptor
          (getSingleLogoutServices)
          (add (doto (.buildObject (SingleLogoutServiceBuilder.))
                 (.setBinding SAMLConstants/SAML2_POST_BINDING_URI)
                 (.setLocation slo-url)))))

    (.. entity-descriptor
        (getRoleDescriptors)
        (add sp-sso-descriptor))
    (coerce/->xml-string (XMLObjectSupport/marshall entity-descriptor))))
