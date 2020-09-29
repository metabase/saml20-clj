(ns saml20-clj.coerce
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [hiccup
             [core :as hiccup]
             [page :as h.page]]
            [saml20-clj
             [encode-decode :as encode-decode]
             [xml :as saml.xml]])
  (:import [clojure.lang IPersistentMap IPersistentVector]
           [java.io ByteArrayInputStream StringWriter]
           [java.security KeyFactory KeyStore PrivateKey PublicKey Security]
           [java.security.cert CertificateFactory X509Certificate]
           java.security.interfaces.RSAPrivateCrtKey
           [java.security.spec PKCS8EncodedKeySpec RSAPublicKeySpec]
           javax.crypto.spec.SecretKeySpec
           [javax.xml.transform OutputKeys TransformerFactory]
           javax.xml.transform.dom.DOMSource
           javax.xml.transform.stream.StreamResult
           org.bouncycastle.jce.provider.BouncyCastleProvider
           org.opensaml.core.config.InitializationService
           org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport
           org.opensaml.core.xml.XMLObject
           org.opensaml.saml.common.SignableSAMLObject
           org.opensaml.saml.saml2.core.Response
           [org.opensaml.security.credential BasicCredential Credential]
           org.opensaml.security.x509.BasicX509Credential
           org.opensaml.security.x509.impl.KeyStoreX509CredentialAdapter
           org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer
           [org.w3c.dom Document Element Node]))

;; these have to be initialized before using.
;;
;; TODO -- consider putting these in their own respective delays and deref inside relevant functions so init is done
;; when they are called rather than when namespace is evaluated.
(defonce ^:private -init
  (do
    ;; add BouncyCastle as a security provider.
    (Security/addProvider (BouncyCastleProvider.))
    ;; initialize OpenSAML
    (InitializationService/initialize)
    ;; verify that OpenSAML has the crypto classes it needs
    (.init (JavaCryptoValidationInitializer.))
    nil))

(defprotocol CoerceToPrivateKey
  (->PrivateKey
   [this]
   [this ^String algorithm]
    "Coerce something such as a base-64-encoded string or byte array to a `PrivateKey`. This isn't used directly by
 OpenSAML -- the key must be passed as part of an OpenSAML `Credential`. See `->Credential`."))

(defprotocol CoerceToX509Certificate
  (^java.security.cert.X509Certificate ->X509Certificate [this]
    "Coerce something such as a base-64-encoded string or byte array to a `java.security.cert.X509Certificate`. This
 class isn't used directly by OpenSAML; instead, certificate must be coerced to an OpenSAML `Credential`. See
`->Credential`."))

(defprotocol CoerceToCredential
  (->Credential
    [this]
    [public-key private-key]
    "Coerce something such as a byte array or base-64-encoded String to an OpenSAML `Credential`. Typically, you'd use
  the credential with just the public key for the IdP's credentials, for encrypting requests (in combination with SP
  credentails) or verifying signature(s) in the response. A credential with both public and private keys would
  typically contain *your* public and private keys, for encrypting requests (in combination with IdP credentials) or
  for decrypting encrypted assertions in the response."))

(defprotocol CoerceToElement
  (^org.w3c.dom.Element ->Element [this]))

(defprotocol CoerceToSAMLObject
  (^org.opensaml.saml.common.SignableSAMLObject ->SAMLObject [this]))

(defprotocol CoerceToResponse
  (^org.opensaml.saml.saml2.core.Response ->Response [this]))

(defprotocol SerializeXMLString
  (^String ->xml-string [this]))


;;; ------------------------------------------------------ Impl ------------------------------------------------------

(defn keystore
  ^KeyStore [{:keys [keystore ^String filename ^String password]}]
  (or keystore
      (when (some-> filename io/as-file .exists)
        (with-open [is (io/input-stream filename)]
          (doto (KeyStore/getInstance "JKS")
            (.load is (.toCharArray password)))))))

(defmulti bytes->PrivateKey
  "Generate a private key from a byte array using the given `algorithm`.

    (bytes->PrivateKey my-byte-array :rsa) ;; -> ..."
  {:arglists '(^PrivateKey [^bytes key-bytes algorithm])}
  (fn [_ algorithm]
    (keyword algorithm)))

(defmethod bytes->PrivateKey :default
  [^bytes key-bytes algorithm]
  (.generatePrivate (KeyFactory/getInstance (str/upper-case (name algorithm)), "BC")
                    (PKCS8EncodedKeySpec. key-bytes)))

(defmethod bytes->PrivateKey :aes
  [^bytes key-bytes _]
  (SecretKeySpec. key-bytes
                  0
                  (count key-bytes)
                  "AES"))

;; I don't think we can use the "class name" of a byte array in `extend-protocol`
(extend (Class/forName "[B")
  CoerceToPrivateKey
  {:->PrivateKey
   (fn
     ([^bytes this]
      (->PrivateKey this :rsa))
     ([^bytes this algorithm]
      (bytes->PrivateKey this algorithm)))})

(extend-protocol CoerceToPrivateKey
  nil
  (->PrivateKey
    ([_] nil)
    ([_ _] nil))

  String
  (->PrivateKey
    ([s] (->PrivateKey s :rsa))
    ([s algorithm] (->PrivateKey (encode-decode/base64-credential->bytes s) algorithm)))

  PrivateKey
  (->PrivateKey
    ([this] this)
    ([this _] this))

  Credential
  (->PrivateKey
    ([this]
     (.getPrivateKey this))
    ([this _]
     (->PrivateKey this)))

  IPersistentMap
  (->PrivateKey
    ([{^String key-alias :alias, ^String password :password, :as m}]
     (when-let [keystore (keystore m)]
       (when-let [key (.getKey keystore key-alias (.toCharArray password))]
         (assert (instance? PrivateKey key))
         key)))
    ([this _]
     (->PrivateKey this)))

  IPersistentVector
  (->PrivateKey
    ([[_ k]]
     (->PrivateKey k))
    ([[_ k] algorithm]
     (->PrivateKey k algorithm))))

(extend (Class/forName "[B")
  CoerceToX509Certificate
  {:->X509Certificate
   (fn [^bytes this]
     (let [cert-factory (CertificateFactory/getInstance "X.509")]
       (with-open [is (ByteArrayInputStream. this)]
         (.generateCertificate cert-factory is))))})

(extend-protocol CoerceToX509Certificate
  nil
  (->X509Certificate [_] nil)

  String
  (->X509Certificate [s]
    (->X509Certificate (encode-decode/base64-credential->bytes s)))

  X509Certificate
  (->X509Certificate [this] this)

  BasicX509Credential
  (->X509Certificate [this]
    (.getEntityCertificate this))

  IPersistentMap
  (->X509Certificate
    [{^String key-alias :alias, ^String password :password, :as m}]
    (when (and key-alias password)
      (when-let [keystore (keystore m)]
        (.getCertificate keystore key-alias)))))

(extend-protocol CoerceToCredential
  nil
  (->Credential
    ([_] nil)
    ([_ _] nil))

  Object
  (->Credential
    ([public-key]
     (->Credential public-key nil))
    ([public-key private-key]
     (let [cert (->X509Certificate public-key)]
       (if private-key
         (BasicX509Credential. cert (->PrivateKey private-key))
         (BasicX509Credential. cert)))))

  IPersistentMap
  (->Credential
    ([{^String key-alias :alias, ^String password :password, :as m}]
     (when (and key-alias password)
       (when-let [keystore (keystore m)]
         (KeyStoreX509CredentialAdapter. keystore key-alias (.toCharArray password)))))
    ([m private-key]
     (let [credential ^Credential (->Credential m)
           public-key (.getPublicKey credential)]
       (->Credential public-key private-key))))

  IPersistentVector
  (->Credential [[public-key private-key]]
    (->Credential public-key private-key))

  PublicKey
  (->Credential [this]
    (BasicCredential. this))

  SecretKeySpec
  (->Credential [this]
    (BasicCredential. this))

  RSAPrivateCrtKey
  (->Credential [this]
    (BasicCredential.
     (.generatePublic (KeyFactory/getInstance "RSA")
                      (RSAPublicKeySpec. (.getModulus this) (.getPublicExponent this)))
     this)))

(extend-protocol CoerceToElement
  nil
  (->Element [_] nil)

  Element
  (->Element [this] this)

  Document
  (->Element [this]
    (.getDocumentElement this))

  XMLObject
  (->Element [this]
    (let [marshaller-factory (XMLObjectProviderRegistrySupport/getMarshallerFactory)
          marshaller         (.getMarshaller marshaller-factory this)]
      (when-not marshaller
        (throw (ex-info (format "Don't know how to marshall %s" (.getCanonicalName (class this)))
                        {:object this})))
      (->Element (.marshall marshaller this))))

  String
  (->Element [this]
    (->Element (saml.xml/str->xmldoc this)))

  ;; hiccup-style xml element
  ;; TODO -- it's a little inefficient to serialize this to a string and then back to an element
  IPersistentVector
  (->Element [this]
    (->Element (->xml-string this))))

(extend-protocol CoerceToSAMLObject
  nil
  (->SAMLObject [_] nil)

  SignableSAMLObject
  (->SAMLObject [this] this)

  Element
  (->SAMLObject [this]
    (let [unmarshaller-factory (XMLObjectProviderRegistrySupport/getUnmarshallerFactory)
          unmarshaller         (.getUnmarshaller unmarshaller-factory this)]
      (when-not unmarshaller
        (throw (ex-info (format "Don't know how to unmarshall %s" (.getCanonicalName (class this)))
                        {:object this})))
      (.unmarshall unmarshaller this)))

  Document
  (->SAMLObject [this]
    (->SAMLObject (.getDocumentElement this)))

  Object
  (->SAMLObject [this]
    (->SAMLObject (->Element this))))

(extend-protocol CoerceToResponse
  nil
  (->Response [_] nil)

  Response
  (->Response [this] this)

  SignableSAMLObject
  (->Response [this]
    (throw (ex-info (format "Don't know how to coerce a %s to a Response" (.getCanonicalName (class this)))
                    {:object this})))

  Object
  (->Response [this]
    (->Response (->SAMLObject this))))

(extend-protocol SerializeXMLString
  nil
  (->xml-string [_] nil)

  String
  (->xml-string [this] this)

  IPersistentVector
  (->xml-string [this]
    (str
     (h.page/xml-declaration "UTF-8")
     (hiccup/html this)))

  Node
  (->xml-string [this]
    (let [transformer (doto (.. TransformerFactory newInstance newTransformer)
                        #_(.setOutputProperty OutputKeys/OMIT_XML_DECLARATION "yes")
                        (.setOutputProperty OutputKeys/ENCODING "UTF-8")
                        (.setOutputProperty OutputKeys/INDENT "yes")
                        (.setOutputProperty "{http://xml.apache.org/xslt}indent-amount" "2"))
          dom-source (DOMSource. this)]
      (with-open [w (StringWriter.)]
        (let [stream-result (StreamResult. w)]
          (.transform transformer dom-source stream-result))
        (.toString w))))

  XMLObject
  (->xml-string [this]
    (->xml-string (.getDOM this))))
