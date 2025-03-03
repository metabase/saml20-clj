(ns saml20-clj.coerce
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [saml20-clj.encode-decode :as encode-decode]
            [saml20-clj.xml :as saml.xml])
  (:import org.opensaml.core.xml.util.XMLObjectSupport
           org.opensaml.saml.common.binding.impl.BaseSAMLHttpServletRequestDecoder
           [org.opensaml.saml.saml2.binding.decoding.impl HTTPPostDecoder HTTPRedirectDeflateDecoder]))

;; these have to be initialized before using.
;;
;; TODO -- consider putting these in their own respective delays and deref inside relevant functions so init is done
;; when they are called rather than when namespace is evaluated.
(defonce ^:private -init
  (delay
    ;; add BouncyCastle as a security provider.
    (java.security.Security/addProvider (org.bouncycastle.jce.provider.BouncyCastleProvider.))
    ;; initialize OpenSAML
    (org.opensaml.core.config.InitializationService/initialize)
    ;; verify that OpenSAML has the crypto classes it needs
    (.init (org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer.))
    nil))

@-init

(defprotocol CoerceToPrivateKey
  (->PrivateKey
    ^java.security.PrivateKey [this]
    ^java.security.PrivateKey [this ^String algorithm]
    "Coerce something such as a base-64-encoded string or byte array to a `PrivateKey`. This isn't used directly by
  OpenSAML -- the key must be passed as part of an OpenSAML `Credential`. See `->Credential`."))

(defprotocol CoerceToX509Certificate
  (->X509Certificate ^java.security.cert.X509Certificate [this]
    "Coerce something such as a base-64-encoded string or byte array to a `java.security.cert.X509Certificate`. This
  class isn't used directly by OpenSAML; instead certificate must be coerced to an OpenSAML `Credential`. See
`->Credential`."))

(defprotocol CoerceToCredential
  (->Credential
    ^org.opensaml.security.credential.Credential [this]
    ^org.opensaml.security.credential.Credential [public-key private-key]
    "Coerce something such as a byte array or base-64-encoded String to an OpenSAML `Credential`. Typically you'd use
  the credential with just the public key for the IdP's credentials for encrypting requests (in combination with SP
  credentails) or verifying signature(s) in the response. A credential with both public and private keys would
  typically contain *your* public and private keys for encrypting requests (in combination with IdP credentials) or
  for decrypting encrypted assertions in the response."))

(defprotocol CoerceToElement
  (->Element ^org.w3c.dom.Element [this]))

(defprotocol CoerceToSAMLObject
  (->SAMLObject ^org.opensaml.saml.common.SignableSAMLObject [this]))

(defprotocol CoerceToResponse
  (->Response ^org.opensaml.saml.saml2.core.Response [this]))

(defprotocol CoerceToLogoutResponse
  (->LogoutResponse ^org.opensaml.saml.saml2.core.LogoutResponse [this]))

(defprotocol SerializeXMLString
  (->xml-string ^String [this]))

;;; ------------------------------------------------------ Impl ------------------------------------------------------

(defn keystore
  ^java.security.KeyStore [{:keys [keystore ^String filename ^String password]}]
  (or keystore
      (when (some-> filename io/as-file .exists)
        (with-open [is (io/input-stream filename)]
          (doto (java.security.KeyStore/getInstance "JKS")
            (.load is (.toCharArray password)))))))

(defmulti bytes->PrivateKey
  "Generate a private key from a byte array using the given `algorithm`.

    (bytes->PrivateKey my-byte-array :rsa) ;; -> ..."
  {:arglists '(^java.security.PrivateKey [^bytes key-bytes algorithm])}
  (fn [_ algorithm]
    (keyword algorithm)))

(defmethod bytes->PrivateKey :default
  [^bytes key-bytes algorithm]
  (.generatePrivate (java.security.KeyFactory/getInstance (str/upper-case (name algorithm))
                                                          "BC")
                    (java.security.spec.PKCS8EncodedKeySpec. key-bytes)))

(defmethod bytes->PrivateKey :aes
  [^bytes key-bytes _]
  (javax.crypto.spec.SecretKeySpec. key-bytes
                                    0
                                    (count key-bytes)
                                    "AES"))

(defn ring-request->HttpServletRequestSupplier
  ^jakarta.servlet.http.HttpServletRequest [request]
  (let [http-request
        (reify jakarta.servlet.http.HttpServletRequest
          (getMethod [_]
            (condp = (:request-method request)
              :post "POST" ;; the HTTPPostDecoder only cares about seeing exactly POST in the request
              :get "GET" ;; the HTTPRedirectDeflateDecode only cares about seeing exactly GET in the request
              "UNKNOWN"))
          (getContentType [_]
            (:content-type request))
          (getQueryString [_]
            (:query-string request))
          (getParameter [_ param]
            (or (get-in request [:params (keyword param)])
                (get-in request [:params param]))))]
    (reify net.shibboleth.shared.primitive.NonnullSupplier
      (get [_] http-request))))

(defn ring-request->MessageContext
  ^org.opensaml.messaging.context.MessageContext [request]
  (let [http-request-supplier (ring-request->HttpServletRequestSupplier request)
        ^BaseSAMLHttpServletRequestDecoder http-decoder (if (= (:request-method request) :post)
                                                          (HTTPPostDecoder.)
                                                          (HTTPRedirectDeflateDecoder.))]
    (doto http-decoder
      (.setHttpServletRequestSupplier http-request-supplier)
      (.initialize)
      (.decode))
    (.getMessageContext http-decoder)))

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

  java.security.PrivateKey
  (->PrivateKey
    ([this] this)
    ([this _] this))

  org.opensaml.security.credential.Credential
  (->PrivateKey
    ([this]
     (.getPrivateKey this))
    ([this _]
     (->PrivateKey this)))

  clojure.lang.IPersistentMap
  (->PrivateKey
    ([{^String key-alias :alias
       ^String password :password
       :as m}]
     (when-let [keystore (keystore m)]
       (when-let [key (.getKey keystore key-alias (.toCharArray password))]
         (assert (instance? java.security.PrivateKey key))
         key)))
    ([this _]
     (->PrivateKey this)))

  clojure.lang.IPersistentVector
  (->PrivateKey
    ([[_ k]]
     (->PrivateKey k))
    ([[_ k] algorithm]
     (->PrivateKey k algorithm))))

(extend (Class/forName "[B")
  CoerceToX509Certificate
  {:->X509Certificate
   (fn [^bytes this]
     (let [cert-factory (java.security.cert.CertificateFactory/getInstance
                         "X.509")]
       (with-open [is (java.io.ByteArrayInputStream. this)]
         (.generateCertificate cert-factory is))))})

(extend-protocol CoerceToX509Certificate
  nil
  (->X509Certificate [_] nil)

  String
  (->X509Certificate [s]
    (->X509Certificate (encode-decode/base64-credential->bytes s)))

  java.security.cert.X509Certificate
  (->X509Certificate [this] this)

  org.opensaml.security.x509.BasicX509Credential
  (->X509Certificate [this]
    (.getEntityCertificate this))

  clojure.lang.IPersistentMap
  (->X509Certificate
    [{^String key-alias :alias
      ^String password :password
      :as m}]
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
         (org.opensaml.security.x509.BasicX509Credential. cert (->PrivateKey private-key))
         (org.opensaml.security.x509.BasicX509Credential. cert)))))

  clojure.lang.IPersistentMap
  (->Credential
    ([{^String key-alias :alias
       ^String password :password
       :as m}]
     (when (and key-alias password)
       (when-let [keystore (keystore m)]
         (org.opensaml.security.x509.impl.KeyStoreX509CredentialAdapter. keystore key-alias (.toCharArray password)))))
    ([m private-key]
     (let [credential (->Credential m)
           public-key (.getPublicKey credential)]
       (->Credential public-key private-key))))

  clojure.lang.IPersistentVector
  (->Credential [[public-key private-key]]
    (->Credential public-key private-key))

  java.security.PublicKey
  (->Credential [this]
    (org.opensaml.security.credential.BasicCredential. this))

  javax.crypto.spec.SecretKeySpec
  (->Credential [this]
    (org.opensaml.security.credential.BasicCredential. this))

  java.security.interfaces.RSAPrivateCrtKey
  (->Credential [this]
    (org.opensaml.security.credential.BasicCredential.
     (.generatePublic (java.security.KeyFactory/getInstance "RSA")
                      (java.security.spec.RSAPublicKeySpec. (.getModulus this) (.getPublicExponent this)))
     this)))

(extend-protocol CoerceToElement
  nil
  (->Element [_] nil)

  org.w3c.dom.Element
  (->Element [this] this)

  org.w3c.dom.Document
  (->Element [this]
    (.getDocumentElement this))

  org.opensaml.core.xml.XMLObject
  (->Element [this]
    (let [marshaller-factory (org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport/getMarshallerFactory)
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
  clojure.lang.IPersistentVector
  (->Element [this]
    (->Element (->xml-string this))))

(extend-protocol CoerceToSAMLObject
  nil
  (->SAMLObject [_] nil)

  org.opensaml.saml.common.SignableSAMLObject
  (->SAMLObject [this] this)

  org.w3c.dom.Element
  (->SAMLObject [this]
    (let [unmarshaller-factory (org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport/getUnmarshallerFactory)
          unmarshaller         (.getUnmarshaller unmarshaller-factory this)]
      (when-not unmarshaller
        (throw (ex-info (format "Don't know how to unmarshall %s" (.getCanonicalName (class this)))
                        {:object this})))
      (.unmarshall unmarshaller this)))

  org.w3c.dom.Document
  (->SAMLObject [this]
    (->SAMLObject (.getDocumentElement this)))

  Object
  (->SAMLObject [this]
    (->SAMLObject (->Element this))))

(extend-protocol CoerceToLogoutResponse
  nil
  (->LogoutResponse [_] nil)

  org.opensaml.saml.saml2.core.LogoutResponse
  (->LogoutResponse [this] this)

  org.opensaml.saml.common.SignableSAMLObject
  (->LogoutResponse [this]
    (throw (ex-info (format "Don't know how to coerce a %s to a Response" (.getCanonicalName (class this)))
                    {:object this})))

  org.opensaml.messaging.context.MessageContext
  (->LogoutResponse [this]
    (->LogoutResponse (.ensureMessage this org.opensaml.saml.saml2.core.LogoutResponse)))

  clojure.lang.IPersistentMap
  (->LogoutResponse [this]
    (->LogoutResponse (ring-request->MessageContext this)))

  Object
  (->LogoutResponse [this]
    (->LogoutResponse (->SAMLObject this))))

(extend-protocol CoerceToResponse
  nil
  (->Response [_] nil)

  org.opensaml.messaging.context.MessageContext
  (->Response [this] (.ensureMessage this org.opensaml.saml.saml2.core.Response))

  org.opensaml.saml.saml2.core.Response
  (->Response [this] this)

  org.opensaml.saml.common.SignableSAMLObject
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

  org.w3c.dom.Node
  (->xml-string [this]
    (let [transformer (doto (.. javax.xml.transform.TransformerFactory newInstance newTransformer)
                        #_(.setOutputProperty javax.xml.transform.OutputKeys/OMIT_XML_DECLARATION "yes")
                        (.setOutputProperty javax.xml.transform.OutputKeys/ENCODING "UTF-8")
                        (.setOutputProperty javax.xml.transform.OutputKeys/INDENT "yes")
                        (.setOutputProperty "{http://xml.apache.org/xslt}indent-amount" "2"))
          dom-source (javax.xml.transform.dom.DOMSource. this)]
      (with-open [w (java.io.StringWriter.)]
        (let [stream-result (javax.xml.transform.stream.StreamResult. w)]
          (.transform transformer dom-source stream-result))
        (.toString w))))

  org.opensaml.core.xml.XMLObject
  (->xml-string [this]
    (->xml-string (.getDOM this)))

  org.opensaml.messaging.context.MessageContext
  (->xml-string [this]
    (->xml-string (XMLObjectSupport/marshall (.getMessage this)))))
