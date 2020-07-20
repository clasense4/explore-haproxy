# Exploring HA Proxy

## Introduction

In this repository we will explore how HA Proxy works. The goal of this implementation is to get understanding how HA Proxy works. The instance is used for **SSL offloading** and proxies around **25000 requests per second**. Also we will explore how to monitor HA Proxy and send our metrics to Prometheus and Grafana.

## Pre-requisite

1. AWS Account
2. Terraform
3. Domain Name


## Tricks

### Validate HA Proxy config

```shell
haproxy -c -V -f /etc/haproxy/haproxy.cfg
```

### Request let's encrypt certificate

```
sudo certbot certonly --dns-route53 -d "*.serverless.my.id" -d serverless.my.id --agree-tos --no-bootstrap --manual-public-ip-logging-ok --preferred-challenges dns-01 --server https://acme-v02.api.letsencrypt.org/directory
```

### Combine let's encrypt certificate and private key

```
sudo cat /etc/letsencrypt/live/serverless.my.id/fullchain.pem \
    /etc/letsencrypt/live/serverless.my.id/privkey.pem \
    | sudo tee serverless.my.id.pem
```

## Vegeta Load test Commands

```
echo "POST https://haproxy.serverless.my.id" | ./vegeta -cpus=2 attack -duration=10m -rate=100 -workers=4  | tee reports.bin | ./vegeta report
# 60K Total request in 1 minute
time echo "POST https://haproxy.serverless.my.id" | vegeta -cpus=1 attack -duration=1m -rate=1000 -workers=50  | tee reports.bin | vegeta report
# 60K Total request in 1 minute
time echo "POST https://haproxy.serverless.my.id" | vegeta -cpus=2 attack -duration=1m -rate=1000 -workers=100  | tee reports.bin | vegeta report
# 120K Total request in 1 minute (Failed)
time echo "POST https://haproxy.serverless.my.id" | vegeta -cpus=2 attack -duration=1m -rate=2000 -workers=100  | tee reports.bin | vegeta report
```

## Resources

### Up and running, concepts

- [https://www.digitalocean.com/community/tutorials/how-to-implement-ssl-termination-with-haproxy-on-ubuntu-14-04](https://www.digitalocean.com/community/tutorials/how-to-implement-ssl-termination-with-haproxy-on-ubuntu-14-04)
- [https://www.digitalocean.com/community/tutorials/an-introduction-to-haproxy-and-load-balancing-concepts](https://www.digitalocean.com/community/tutorials/an-introduction-to-haproxy-and-load-balancing-concepts)
- [https://www.digitalocean.com/community/tutorial_series/load-balancing-wordpress-with-haproxy](https://www.digitalocean.com/community/tutorial_series/load-balancing-wordpress-with-haproxy)
- [https://www.linode.com/docs/uptime/loadbalancing/how-to-use-haproxy-for-load-balancing/](https://www.linode.com/docs/uptime/loadbalancing/how-to-use-haproxy-for-load-balancing/)
- [https://serversforhackers.com/c/letsencrypt-with-haproxy](https://serversforhackers.com/c/letsencrypt-with-haproxy)
- [https://www.haproxy.com/blog/the-four-essential-sections-of-an-haproxy-configuration/](https://www.haproxy.com/blog/the-four-essential-sections-of-an-haproxy-configuration/)


### Monitoring

- [https://www.haproxy.com/blog/exploring-the-haproxy-stats-page/](https://www.haproxy.com/blog/exploring-the-haproxy-stats-page/)
- [https://github.com/prometheus/haproxy_exporter](https://github.com/prometheus/haproxy_exporter)
- [https://www.haproxy.com/blog/haproxy-exposes-a-prometheus-metrics-endpoint/](https://www.haproxy.com/blog/haproxy-exposes-a-prometheus-metrics-endpoint/)


### Load test HA Proxy

- [https://medium.com/@sachinmalhotra/load-testing-haproxy-part-1-f7d64500b75d](https://medium.com/@sachinmalhotra/load-testing-haproxy-part-1-f7d64500b75d)
- [https://medium.com/@sachinmalhotra/load-testing-haproxy-part-2-4c8677780df6](https://medium.com/@sachinmalhotra/load-testing-haproxy-part-2-4c8677780df6)
- [https://medium.com/free-code-camp/how-we-fine-tuned-haproxy-to-achieve-2-000-000-concurrent-ssl-connections-d017e61a4d27](https://medium.com/free-code-camp/how-we-fine-tuned-haproxy-to-achieve-2-000-000-concurrent-ssl-connections-d017e61a4d27)