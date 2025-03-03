(ns saml20-clj.encode-decode
  "Utility functions for encoding/decoding and compressing byte arrays and strings."
  (:require [clojure.string :as str])
  (:import [java.io ByteArrayInputStream ByteArrayOutputStream]
           [java.util.zip Deflater DeflaterOutputStream Inflater InflaterInputStream]
           [org.apache.commons.codec.binary Base64 Hex]
           org.apache.commons.io.IOUtils))

(defn str->bytes
  ^bytes [^String some-string]
  (when some-string
    (.getBytes some-string "UTF-8")))

(defn bytes->str
  ^String [^bytes some-bytes]
  (when some-bytes
    (String. some-bytes "UTF-8")))

(defn strip-ascii-armor
  ^String [^String s]
  (when s
    (-> s
        (str/replace #"-----BEGIN [A-Z\s]+-----" "")
        (str/replace #"-----END [A-Z\s]+-----" "")
        (str/replace #"[\n ]" ""))))

(defn decode-base64 ^bytes [^bytes bs]
  (when bs
    (Base64/decodeBase64 bs)))

(defn encode-base64 ^bytes [^bytes bs]
  (when bs
    (Base64/encodeBase64 bs)))

(defn base64-credential->bytes ^bytes [^String s]
  (when s
    (decode-base64 (str->bytes (strip-ascii-armor s)))))

(defn byte-deflate
  ^bytes [^bytes str-bytes]
  (with-open [byte-os     (ByteArrayOutputStream.)
              deflater-os (DeflaterOutputStream. byte-os (Deflater. -1 true) 1024)]
    (.write deflater-os str-bytes)
    (.finish deflater-os)
    (.toByteArray byte-os)))

(defn byte-inflate
  ^bytes [^bytes comp-bytes]
  (with-open [is (InflaterInputStream. (ByteArrayInputStream. comp-bytes) (Inflater. true) 1024)]
    (IOUtils/toByteArray is)))

(defn str->base64
  ^String [^String string]
  (-> string str->bytes encode-base64 bytes->str))

(defn str->deflate->base64
  ^String [^String string]
  (-> string str->bytes byte-deflate encode-base64 bytes->str))

(defn base64->str
  ^String [^String string]
  (-> string str->bytes decode-base64 bytes->str))

(defn base64->inflate->str
  ^String [^String string]
  (-> string str->bytes decode-base64 byte-inflate bytes->str))

(defn bytes->hex
  ^String [^bytes bytes-str]
  (Hex/encodeHexString bytes-str))
