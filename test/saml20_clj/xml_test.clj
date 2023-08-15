(ns saml20-clj.xml-test
  (:require [clojure.test :refer :all]
            [saml20-clj.xml :as xml]))

(deftest str->xmldoc-test
  (testing "str->xmldoc errors if the input XML contains a DOCTYPE declaration"
    (let [xml-str (str
                   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                   "<!DOCTYPE root [<!ENTITY test SYSTEM 'http://example.com'>]>"
                   "<root>&test;</root>")]
      (is (thrown? org.xml.sax.SAXParseException
                   (xml/str->xmldoc xml-str))))))
