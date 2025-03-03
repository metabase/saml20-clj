(ns saml20-clj.sp.metadata-test
  (:require [clojure.test :as t]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.sp.metadata :as sut]
            [saml20-clj.test :as test]))

(t/deftest metadata-generation
  (t/testing "generates metadata with keyinfo"
    (t/is (= test/metadata-with-key-info
             (saml20-clj.sp.metadata/metadata {:app-name "metabase"
                                               :acs-url "http://acs.example.com"
                                               :slo-url "http://slo.example.com"
                                               :sp-cert (coerce/->Credential test/sp-cert)}))))
  (t/testing "generates metadata with-out keyinfo"
    (t/is (= test/metadata-without-key-info
             (saml20-clj.sp.metadata/metadata {:app-name "metabase"
                                               :acs-url "http://acs.example.com"
                                               :slo-url "http://slo.example.com"})))))
