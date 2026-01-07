# TLSA_RecordCheck
Bash script to check local certs and update TLSA DNS records in Cloudflare

Pulls in a list of domains to check and updates the records in cloudflare. 

The list should be built like this

domain.com 1234domain1cloudflareapikeyabc 1234domain1cloudflarezoneidabc\
domain2.com 1234domain2cloudflareapikeyabc 1234domain2cloudflarezoneidabc

# Env Vars
Set these up on the user executing this, if setting up in cron set them up for root.\
You could also modify the vars in the script to pull in from a file
```
export SCRIPTSMTPTO=alerting@address.com
export SCRIPTCERT_PATH=/mnt/containers/swag/etc/letsencrypt/live/
export SCRIPTSMTPFROM=notification@fromaddress.net 
export SCRIPTSOURCE_DOMAINS=/home/user/activeDomainsHash
```

# Requirements
`apt install jq openssl nullmailer`

