# A사 웹서버. 운영 형태의 Apache 2.4(mod_ssl, mod_proxy) 자리다.
FROM httpd:2.4

# 필요한 모듈만 켠다
RUN sed -i \
    -e 's|^#\(LoadModule proxy_module\)|\1|' \
    -e 's|^#\(LoadModule proxy_http_module\)|\1|' \
    -e 's|^#\(LoadModule ssl_module\)|\1|' \
    -e 's|^#\(LoadModule socache_shmcb_module\)|\1|' \
    -e 's|^#\(LoadModule headers_module\)|\1|' \
    -e 's|^#\(LoadModule rewrite_module\)|\1|' \
    conf/httpd.conf \
 && printf '\nInclude conf/extra/ekyc-tls.conf\nInclude conf/ekyc.conf\n' >> conf/httpd.conf

COPY tls.conf conf/extra/ekyc-tls.conf
