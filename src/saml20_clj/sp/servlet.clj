(ns saml20-clj.sp.servlet
  "Jakarta servlet implementation for SAML request handling")

(set! *warn-on-reflection* true)

(defn map-making-servlet
  "Implements a complete HttpServletResponse for HTTPRedirectDeflateEncoder"
  []
  (let [response (atom {:status 302 :body "" :headers {}})
        servlet-wrapper (reify jakarta.servlet.http.HttpServletResponse
                          ;; Redirect methods
                          (sendRedirect [this redirect]
                            (.setHeader this "location" redirect))
                          (sendError [_this _sc])
                          (sendError [_this _sc _msg])

                          ;; Header methods
                          (setHeader [_this name value]
                            (swap! response update :headers assoc name value))
                          (addHeader [_this name value]
                            (swap! response update :headers
                                   #(update % name
                                            (fn [existing]
                                              (if existing
                                                (str existing "," value)
                                                value)))))
                          (setIntHeader [this name value]
                            (.setHeader this name (str value)))
                          (addIntHeader [this name value]
                            (.addHeader this name (str value)))
                          (setDateHeader [this name date]
                            (.setHeader this name (str date)))
                          (addDateHeader [this name date]
                            (.addHeader this name (str date)))
                          (containsHeader [_this name]
                            (contains? (:headers @response) name))

                          ;; Status methods
                          (setStatus [_this sc]
                            (swap! response assoc :status sc))
                          (getStatus [_this]
                            (:status @response))

                          ;; Content type and encoding
                          (setContentType [_this type]
                            (swap! response update :headers assoc "Content-Type" type))
                          (getContentType [_this]
                            (get-in @response [:headers "Content-Type"]))
                          (^void setCharacterEncoding [_this ^String _encoding])
                          (getCharacterEncoding [_this] "UTF-8")

                          ;; Content length
                          (setContentLength [_this len]
                            (swap! response update :headers assoc "Content-Length" (str len)))
                          (setContentLengthLong [_this len]
                            (swap! response update :headers assoc "Content-Length" (str len)))

                          ;; Locale
                          (setLocale [_this _locale])
                          (getLocale [_this] (java.util.Locale/getDefault))

                          ;; Buffer management
                          (getBufferSize [_this] 8192)
                          (setBufferSize [_this _size])
                          (isCommitted [_this] false)
                          (reset [_this])
                          (resetBuffer [_this])
                          (flushBuffer [_this])

                          ;; Output streams (return dummy implementations)
                          (getOutputStream [_this]
                            (proxy [jakarta.servlet.ServletOutputStream] []
                              (write [_b])
                              (isReady [] true)
                              (setWriteListener [_listener])))
                          (getWriter [_this]
                            (java.io.PrintWriter.
                             (java.io.StringWriter.)))

                          ;; Cookies
                          (addCookie [_this _cookie])

                          ;; URL encoding
                          (encodeURL [_this url] url)
                          (encodeRedirectURL [_this url] url)

                          ;; HTTP/2 trailer support
                          (getTrailerFields [_this]
                            (reify java.util.function.Supplier
                              (get [_] {})))
                          (setTrailerFields [_this _supplier])

                          ;; Header collections (ServletResponse interface)
                          (getHeader [_this name]
                            (get-in @response [:headers name]))
                          (getHeaders [_this name]
                            (if-let [header (get-in @response [:headers name])]
                              [header]
                              []))
                          (getHeaderNames [_this]
                            (keys (:headers @response))))
        wrapper-supplier (reify net.shibboleth.shared.primitive.NonnullSupplier
                           (get [_] servlet-wrapper))]
    [wrapper-supplier #(deref response)]))
