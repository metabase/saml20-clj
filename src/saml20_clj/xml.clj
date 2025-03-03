(ns saml20-clj.xml
  (:require [saml20-clj.encode-decode :as encode-decode])
  (:import [javax.xml.parsers DocumentBuilder DocumentBuilderFactory]
           javax.xml.XMLConstants
           org.w3c.dom.Document))

(set! *warn-on-reflection* true)

(defn- document-builder
  ^DocumentBuilder []
  (.newDocumentBuilder
   (doto (DocumentBuilderFactory/newInstance)
     (.setNamespaceAware true)
     (.setFeature "http://xml.org/sax/features/external-parameter-entities" false)
     (.setFeature "http://apache.org/xml/features/nonvalidating/load-external-dtd" false)
     (.setFeature "http://apache.org/xml/features/disallow-doctype-decl" true)
     (.setFeature XMLConstants/FEATURE_SECURE_PROCESSING true)
     (.setXIncludeAware false)
     (.setExpandEntityReferences false))))

(defn clone-document
  "Return a clone of the provided XML document."
  [^org.w3c.dom.Document document]
  (when document
    (let [clone         (.. (DocumentBuilderFactory/newInstance) newDocumentBuilder newDocument)
          original-root (.getDocumentElement document)
          root-copy     (.importNode clone original-root true)]
      (.appendChild clone root-copy)
      clone)))

(defn str->xmldoc
  "Parse a string into an XML `Document`."
  ^Document [^String s]
  (let [document (document-builder)]
    (with-open [is (java.io.ByteArrayInputStream. (encode-decode/str->bytes s))]
      (.parse document is))))
