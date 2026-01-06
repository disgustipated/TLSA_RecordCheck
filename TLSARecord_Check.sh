#! /bin/bash
#script to check TLSA dns records against certs
#functions for interacting with CF api modified from reference https://github.com/fazelukario/cloudflare-tlsa-acmesh.sh/tree/main
#requirements : jq openssl nullmailer
#--VARS FOR CERTS ---------------------
#SOURCE_DOMAINS - env var which is a path that points to a file that contains a list of domains to handle certificates 
#- this file should contain a list like the following, each domain on its own line separated by a space:
#domain cfapitoken cfzoneid
SOURCE_DOMAINS=$SCRIPTSOURCE_DOMAINS
#env var which is a path to where the certs live from certbot
CERT_SRCPATH=$SCRIPTCERT_PATH
allclear=true
#set env vars for SCRIPTSMTPFROM and SCRIPTSMTPTO for notifications

PORT=${PORT:-25}
#my mail domains all have "mail" after _25.tcp for the tlsa record
PROTOCOL=${PROTOCOL:-"tcp.mail"}
CF_API="https://api.cloudflare.com/client/v4/zones"
USAGE=3
SELECTOR=1
MATCHING_TYPE=1

declare -A apiHash
declare -A zoneHash
while read -r domain api zone; do
  apiHash["$domain"]="$api"
  zoneHash["$domain"]="$zone"
done < $SOURCE_DOMAINS

# Logging function
log() {
  echo "[$(date)] $1"
}
# Function to send an email with nullmailer
send_email() {
    local subject="$1"
    local to="$2"
    from=$SCRIPTSMTPFROM
    local body="$3"
    local sendername="TLSA Check"
    local ltlt="<"
    local gtgt=">"

echo "Subject: $subject
To: $to
From: $sendername  $ltlt$from$gtgt

$body" | nullmailer-inject -h
}

# Function to get TLSA records
get_tlsa_records() {
  zone_id="$1"
  api_token="$2"
  domain="$3"
  url="${CF_API}/${zone_id}/dns_records?name=_${PORT}._${PROTOCOL}.${domain}"
  # Capture both status code and response
  response=$(curl -s -w "\n%{http_code}" -X GET -H "Authorization: Bearer $api_token" "$url")
  http_code=$(echo "$response" | tail -n 1)
  response_body=$(echo "$response" | sed '$d')
  # Check HTTP status code
  if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
    echo "$response_body"
  else
    log "Failed to get TLSA records. HTTP status code: $http_code, response: $response_body" >&2
    exit 1
  fi
}

modify_tlsa_record() {
  zone_id="$1"
  api_token="$2"
  domain="$3"
  cert_hash="$4"
  record_id="$5"

  echo "Modifying TLSA record $record_id with cert hash: $cert_hash"
  url="${CF_API}/${zone_id}/dns_records/$record_id"
  payload=$(cat <<EOF
{
  "type": "TLSA",
  "name": "_${PORT}._${PROTOCOL}.${domain}",
  "data": {
    "usage": $USAGE,
    "selector": $SELECTOR,
    "matching_type": $MATCHING_TYPE,
    "certificate": "$cert_hash"
  }
}
EOF
)

  response=$(curl -s -w "\n%{http_code}" -X PUT -H "Authorization: Bearer $api_token" -H "Content-Type: application/json" \
    -d "$payload" "$url")
  http_code=$(echo "$response" | tail -n 1)
  response_body=$(echo "$response" | sed '$d')

  if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
    echo "TLSA record modified successfully."
  else
    echo "Failed to modify TLSA record $record_id. HTTP status code: $http_code, response: $response_body" >&2
    exit 1
  fi
}

log "Begin TLSA Checks"
log "check tlsa record matches"
for domainname in "${!apiHash[@]}"; do
  log "generate current cert value for "${CERT_SRCPATH}$domainname
  cert_hash=$(openssl x509 -in $CERT_SRCPATH$domainname/cert.pem -pubkey -noout | openssl ec -pubin -outform der 2>/dev/null | sha256sum | cut -f 1 -d " ")
  log $cert_hash

  log "get dns record for "${domainname}
  readarray -t TLSA_ARRAY < <(dig _25._tcp.mail.${domainname} tlsa +short)
  IFS=" "
  array=( $TLSA_ARRAY )
  dnsrecord=$(echo "${array[3]}${array[4]}" | tr '[:upper:]' '[:lower:]')
  log $dnsrecord

  if [ "$cert_hash" = "$dnsrecord" ]; then
    log "cert hash and dns record are equal"
  else
    allclear=false
    CF_return=$(get_tlsa_records ${zoneHash[$domainname]} ${apiHash[$domainname]} $domainname)
    CF_record_id=$(echo $CF_return | jq -r '.result[].id')
    modify_tlsa_record ${zoneHash[$domainname]} ${apiHash[$domainname]} $domainname $cert_hash $CF_record_id
    send_email "$domainname TLSA Record Required Update" $SCRIPTSMTPTO "$domainname needed a TLSA record update 
    cert hash was: $cert_hash 
    current dns record was: $dnsrecord"
  fi
done

if [ "$allclear" = true ]; then
  send_email "TLSA Records Clear" $SCRIPTSMTPTO "All domains TLSA are matching"
fi
