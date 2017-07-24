# lua-resty-s3-auth-proxy
This library is designed to act as an incoming and outgoing S3 request proxy.

That is - it will validate incoming requests against a set of access / secret key pairs, verifying each inbound request, and will then proxy the request onwards with a new access / secret key pair.

In particular, this library is designed to be placed in front of the Minio object storage server, to provide per-server access / secret keypairs, and restricting servers to a list of buckets based on their hostname.

This allows a single Minio object storage server instance to provide segregated S3 storage without having to setup multiple instances with different ports and proxies.

```
http {
  lua_shared_dict minio 10m;
  resolver 8.8.8.8 8.8.4.4;
  init_worker_by_lua_block
  {
      local s3_auth        = require('resty.s3-auth-proxy')

      if not auth_proxy then
         auth_proxy = s3_auth:new({
           keys = {
             "test-server01.domain.com" = {
               "aws_access_key_id":     "HXY344T0MWQW5......",
               "aws_secret_access_key": "MVWBdm1gJ420KqkrImD........"
             },
             "test-server02.domain.com" = {
               "aws_access_key_id":     "HXY344T0MWQW5......",
               "aws_secret_access_key": "MVWBdm1gJ420KqkrImD........"
             },
           }
         })
      end
  }

  server {
      listen 80 default_server;
      listen 443 ssl default_server;

      server_name minio.domain.com;

      location / {
          client_body_buffer_size 1024m;
          client_max_body_size 1024m;
          client_body_in_single_buffer on;

          access_by_lua_block { auth_proxy:authenticate() }
          proxy_buffering off;
          proxy_set_header Host $http_host;
          proxy_pass http://<minio host>/;
      }
  }
}

```
