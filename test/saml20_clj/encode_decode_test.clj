(ns saml20-clj.encode-decode-test
  (:require [clojure.test :refer :all]
            [saml20-clj.encode-decode :as encode-decode])
  (:import java.io.ByteArrayInputStream
           org.apache.commons.io.IOUtils))

(def ^:private test-string
  "Th1s 15 50m3 s7r1ng w17h 13773r5 and numb3rs!")

(deftest bytes->str-test
  (testing "Testing string to stream and stream to string transformations."
    (is (= test-string
           (encode-decode/bytes->str (with-open [is (ByteArrayInputStream. (encode-decode/str->bytes test-string))]
                                       (IOUtils/toByteArray is))))))
  (testing "make sure we can encode string -> bytes -> hex"
    (is (= "41424358595a"
           (-> "ABCXYZ" encode-decode/str->bytes encode-decode/bytes->hex)))))

(deftest base-64-test
  (testing "make sure conversion to/from base 64 works as expected"
    (is (= "QUJDREVG"
           (encode-decode/str->base64 "ABCDEF")))
    (is (= "ABCDEF"
           (encode-decode/base64->str "QUJDREVG")))))

(deftest base-64-deflate-inflate-test
  (testing "make sure conversion from base 64 w/ DEFLATE compression works as expected"
    (is (= "ABCDEF"
           (encode-decode/base64->inflate->str "c3RydnF1AwA="))))

  (testing "we should be able to decode base-64 stuff that contains newlines in it"
    (is (= "ABCDEF"
           (encode-decode/base64->inflate->str "c3Ry\ndnF1\r\nAwA=")))
    (is (= "ABCDEF"
           (encode-decode/base64->str "QUJDR\nEV\r\nG")))))
