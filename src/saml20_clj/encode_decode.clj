(ns saml20-clj.encode-decode
  "Utility functions for encoding/decoding and compressing byte arrays and strings."
  (:require [clojure.string :as str])
  (:import [org.apache.commons.codec.binary Base64]))

(set! *warn-on-reflection* true)

(defn str->bytes
  "Return a byte array from a String."
  ^bytes [^String some-string]
  (when some-string
    (.getBytes some-string "UTF-8")))

(defn- strip-ascii-armor
  ^String [^String s]
  (when s
    (-> s
        (str/replace #"-----BEGIN [A-Z\s]+-----" "")
        (str/replace #"-----END [A-Z\s]+-----" "")
        (str/replace #"[\n ]" ""))))

(defn decode-base64
  "Return a decoded byte array from a base64 encoded byte array."
  ^bytes [^bytes bs]
  (when bs
    (Base64/decodeBase64 bs)))

(defn base64-credential->bytes
  "Return a byte array from a base64 encoded security credential string."
  ^bytes [^String s]
  (when s
    (decode-base64 (str->bytes (strip-ascii-armor s)))))
