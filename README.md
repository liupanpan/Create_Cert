g++ certcreate.cpp -I/usr/local/include/  -L/usr/local/lib/ -lssl -lcrypto -o test
查看客户端证书的内容：
openssl x509 -noout -text -in cl_unsigned.pem


