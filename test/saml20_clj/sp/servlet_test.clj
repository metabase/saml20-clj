(ns saml20-clj.sp.servlet-test
  (:require [clojure.test :refer [deftest is testing]]
            [saml20-clj.sp.servlet :as servlet])
  (:import
   [jakarta.servlet.http Cookie]
   [java.util Locale]))

(set! *warn-on-reflection* true)

(deftest map-making-servlet-basic-test
  (testing "Basic servlet creation and response extraction"
    (let [[supplier response-fn] (servlet/map-making-servlet)
          servlet-resp (.get supplier)]
      (is (instance? jakarta.servlet.http.HttpServletResponse servlet-resp))
      (is (fn? response-fn))
      (is (= {:status 302 :body "" :headers {}} (response-fn))))))

(deftest header-management-test
  (testing "Header setting and retrieval"
    (let [[supplier response-fn] (servlet/map-making-servlet)
          servlet-resp (.get supplier)]

      (testing "setHeader and getHeader"
        (.setHeader servlet-resp "Content-Type" "application/xml")
        (is (= "application/xml" (.getHeader servlet-resp "Content-Type")))
        (is (= {"Content-Type" "application/xml"} (:headers (response-fn)))))

      (testing "addHeader for multiple values"
        (.addHeader servlet-resp "Accept" "text/html")
        (.addHeader servlet-resp "Accept" "application/xml")
        (is (= "text/html,application/xml" (.getHeader servlet-resp "Accept"))))

      (testing "containsHeader"
        (is (true? (.containsHeader servlet-resp "Content-Type")))
        (is (false? (.containsHeader servlet-resp "Non-Existent"))))

      (testing "getHeaders returns collection"
        (is (= ["application/xml"] (.getHeaders servlet-resp "Content-Type")))
        (is (= [] (.getHeaders servlet-resp "Non-Existent"))))

      (testing "getHeaderNames returns all header names"
        (is (contains? (set (.getHeaderNames servlet-resp)) "Content-Type"))
        (is (contains? (set (.getHeaderNames servlet-resp)) "Accept"))))))

(deftest typed-header-methods-test
  (testing "Integer and date header methods"
    (let [[supplier _response-fn] (servlet/map-making-servlet)
          servlet-resp (.get supplier)]

      (testing "setIntHeader"
        (.setIntHeader servlet-resp "Content-Length" 1024)
        (is (= "1024" (.getHeader servlet-resp "Content-Length"))))

      (testing "addIntHeader"
        (.addIntHeader servlet-resp "Custom-Int" 42)
        (.addIntHeader servlet-resp "Custom-Int" 24)
        (is (= "42,24" (.getHeader servlet-resp "Custom-Int"))))

      (testing "setDateHeader"
        (.setDateHeader servlet-resp "Last-Modified" 1234567890000)
        (is (= "1234567890000" (.getHeader servlet-resp "Last-Modified"))))

      (testing "addDateHeader"
        (.addDateHeader servlet-resp "Custom-Date" 1111111111111)
        (is (= "1111111111111" (.getHeader servlet-resp "Custom-Date")))))))

(deftest status-management-test
  (testing "Status setting and retrieval"
    (let [[supplier response-fn] (servlet/map-making-servlet)
          servlet-resp (.get supplier)]

      (testing "Default status is 302"
        (is (= 302 (.getStatus servlet-resp))))

      (testing "setStatus updates status"
        (.setStatus servlet-resp 200)
        (is (= 200 (.getStatus servlet-resp)))
        (is (= 200 (:status (response-fn))))))))

(deftest content-type-and-encoding-test
  (testing "Content type and character encoding"
    (let [[supplier _response-fn] (servlet/map-making-servlet)
          servlet-resp (.get supplier)]

      (testing "setContentType and getContentType"
        (.setContentType servlet-resp "text/html; charset=UTF-8")
        (is (= "text/html; charset=UTF-8" (.getContentType servlet-resp))))

      (testing "getCharacterEncoding returns UTF-8 by default"
        (is (= "UTF-8" (.getCharacterEncoding servlet-resp))))

      (testing "setCharacterEncoding is a no-op but doesn't error"
        (.setCharacterEncoding servlet-resp "ISO-8859-1")
        ;; Should still return UTF-8 as it's a dummy implementation
        (is (= "UTF-8" (.getCharacterEncoding servlet-resp)))))))

(deftest content-length-test
  (testing "Content length methods"
    (let [[supplier _response-fn] (servlet/map-making-servlet)
          servlet-resp (.get supplier)]

      (testing "setContentLength"
        (.setContentLength servlet-resp 2048)
        (is (= "2048" (.getHeader servlet-resp "Content-Length"))))

      (testing "setContentLengthLong"
        (.setContentLengthLong servlet-resp 9876543210)
        (is (= "9876543210" (.getHeader servlet-resp "Content-Length")))))))

(deftest locale-test
  (testing "Locale management"
    (let [[supplier _response-fn] (servlet/map-making-servlet)
          servlet-resp (.get supplier)]

      (testing "getLocale returns default locale"
        (is (instance? Locale (.getLocale servlet-resp))))

      (testing "setLocale is a no-op but doesn't error"
        (.setLocale servlet-resp Locale/FRENCH)
        ;; Still returns default locale as it's a dummy implementation
        (is (instance? Locale (.getLocale servlet-resp)))))))

(deftest buffer-management-test
  (testing "Buffer management methods"
    (let [[supplier _response-fn] (servlet/map-making-servlet)
          servlet-resp (.get supplier)]

      (testing "getBufferSize returns default 8192"
        (is (= 8192 (.getBufferSize servlet-resp))))

      (testing "isCommitted returns false"
        (is (false? (.isCommitted servlet-resp))))

      (testing "Buffer methods don't throw exceptions"
        (.setBufferSize servlet-resp 4096)
        (.reset servlet-resp)
        (.resetBuffer servlet-resp)
        (.flushBuffer servlet-resp)
        ;; All should complete without error
        (is true)))))

(deftest output-stream-test
  (testing "Output stream methods"
    (let [[supplier _response-fn] (servlet/map-making-servlet)
          servlet-resp (.get supplier)]

      (testing "getOutputStream returns ServletOutputStream"
        (let [output-stream (.getOutputStream servlet-resp)]
          (is (instance? jakarta.servlet.ServletOutputStream output-stream))
          (is (true? (.isReady output-stream)))
          ;; write method should not throw
          (.write output-stream 65)))

      (testing "getWriter returns PrintWriter"
        (let [writer (.getWriter servlet-resp)]
          (is (instance? java.io.PrintWriter writer)))))))

(deftest cookie-test
  (testing "Cookie management"
    (let [[supplier _response-fn] (servlet/map-making-servlet)
          servlet-resp (.get supplier)]

      (testing "addCookie doesn't throw exception"
        (let [cookie (Cookie. "test" "value")]
          (.addCookie servlet-resp cookie)
          ;; Should complete without error
          (is true))))))

(deftest url-encoding-test
  (testing "URL encoding methods"
    (let [[supplier _response-fn] (servlet/map-making-servlet)
          servlet-resp (.get supplier)]

      (testing "encodeURL returns URL unchanged"
        (is (= "http://example.com" (.encodeURL servlet-resp "http://example.com"))))

      (testing "encodeRedirectURL returns URL unchanged"
        (is (= "https://test.com/path" (.encodeRedirectURL servlet-resp "https://test.com/path")))))))

(deftest trailer-support-test
  (testing "HTTP/2 trailer support"
    (let [[supplier _response-fn] (servlet/map-making-servlet)
          servlet-resp (.get supplier)]

      (testing "getTrailerFields returns supplier with empty map"
        (let [supplier (.getTrailerFields servlet-resp)]
          (is (instance? java.util.function.Supplier supplier))
          (is (= {} (.get supplier)))))

      (testing "setTrailerFields doesn't throw exception"
        (.setTrailerFields servlet-resp
                           (reify java.util.function.Supplier
                             (get [_] {})))
        (is true)))))

(deftest redirect-functionality-test
  (testing "Redirect functionality - the primary use case"
    (let [[supplier response-fn] (servlet/map-making-servlet)
          servlet-resp (.get supplier)]

      (testing "sendRedirect sets location header"
        (.sendRedirect servlet-resp "https://idp.example.com/sso")
        (is (= "https://idp.example.com/sso" (.getHeader servlet-resp "location")))
        (is (= "https://idp.example.com/sso" (get-in (response-fn) [:headers "location"]))))

      (testing "sendError methods don't throw exceptions"
        (.sendError servlet-resp 404)
        (.sendError servlet-resp 500 "Internal Server Error")
        (is true)))))

(deftest integration-test
  (testing "Complete workflow simulation"
    (let [[supplier response-fn] (servlet/map-making-servlet)
          servlet-resp (.get supplier)]

      ;; Simulate typical SAML redirect workflow
      (.setStatus servlet-resp 302)
      (.setHeader servlet-resp "Cache-Control" "no-cache")
      (.sendRedirect servlet-resp "https://idp.example.com/sso?SAMLRequest=...")
      (.setContentType servlet-resp "text/html")

      (let [final-response (response-fn)]
        (is (= 302 (:status final-response)))
        (is (= "https://idp.example.com/sso?SAMLRequest=..."
               (get-in final-response [:headers "location"])))
        (is (= "no-cache"
               (get-in final-response [:headers "Cache-Control"])))
        (is (= "text/html"
               (get-in final-response [:headers "Content-Type"])))))))
