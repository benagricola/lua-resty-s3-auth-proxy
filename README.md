# lua-resty-s3-auth-proxy
Verify incoming S3 V4 requests, then proxy them onwards with a different S3 keypair.

```
http {
  lua_shared_dict minio 10m;
  resolver 8.8.8.8 8.8.4.4;
  init_worker_by_lua_block
  {
      local s3_auth        = require('resty.s3-auth-proxy')

      if not auth_proxy then
         auth_proxy = s3_auth:new({ keys = { "test-server01.domain.com" = {"aws_access_key_id":"HXY344T0MWQW5......","aws_secret_access_key":"MVWBdm1gJ420KqkrImD........"}}})
      end
  }
  
  server {
      listen 80 default_server;
      listen 443 ssl default_server;

      server_name minio.domain.com;

      location / {
          access_by_lua_block { auth_proxy:authenticate() }
          proxy_buffering off;
          proxy_set_header Host $http_host;
          proxy_pass http://<minio host>/;
      }
  }
}

```
