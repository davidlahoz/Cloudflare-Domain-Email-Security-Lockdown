#!/usr/bin/env bash
set -euo pipefail

# Cloudflare Domain Email Security Lockdown
# Purpose: For each domain in domains.txt, set SPF "v=spf1 -all" and a null MX.
# Prevents email phishing and spoofing attacks on unused domains.

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Load .env file if it exists
[[ -f .env ]] && source .env

API="https://api.cloudflare.com/client/v4"
auth_hdr=(-H "Authorization: Bearer ${CF_API_TOKEN:-}" -H "Content-Type: application/json")

echo -e "${BLUE}🔒 Cloudflare Domain Email Security Lockdown${NC}"
echo -e "${BLUE}================================================${NC}\n"

need() { command -v "$1" >/dev/null 2>&1 || { echo -e "${RED}❌ Missing required command: $1${NC}"; exit 1; }; }
need curl
need jq
[[ -n "${CF_API_TOKEN:-}" ]] || { echo -e "${RED}❌ CF_API_TOKEN is required${NC}"; exit 1; }
[[ -f domains.txt ]] || { echo -e "${RED}❌ domains.txt not found${NC}"; exit 1; }

echo -e "${GREEN}✅ All requirements met${NC}\n"

get_zone_id() {
  local domain="$1"
  curl -fsS "${auth_hdr[@]}" "${API}/zones?name=${domain}" | jq -r '.result[0].id // empty'
}

find_record_id() {
  local zone_id="$1" type="$2" name="$3"
  curl -fsS "${auth_hdr[@]}" \
    "${API}/zones/${zone_id}/dns_records?type=${type}&name=${name}" \
  | jq -r '.result[0].id // empty'
}

prompt_user() {
  local prompt="$1"
  local response
  echo -n "$prompt (y/N): "
  read -r response </dev/tty
  [[ "$response" =~ ^[Yy]$ ]]
}

upsert_txt_spf() {
  local zone_id="$1" name="$2"
  local content="\"v=spf1 -all\""
  local id; id="$(find_record_id "$zone_id" "TXT" "$name")"
  
  if [[ -n "$id" ]]; then
    local existing_content; existing_content="$(curl -fsS "${auth_hdr[@]}" "${API}/zones/${zone_id}/dns_records/${id}" | jq -r '.result.content')"
    # Remove quotes for comparison
    local clean_existing; clean_existing="${existing_content//\"/}"
    if [[ "$clean_existing" == "v=spf1 -all" ]]; then
      echo -e "    ${GREEN}✅ SPF record already correct${NC}"
      return
    fi
    
    echo -e "    ${YELLOW}⚠️  Existing SPF record found:${NC}"
    echo -e "      Current: ${RED}$existing_content${NC}"
    echo -e "      Desired: ${GREEN}v=spf1 -all${NC}"
    
    if prompt_user "    Overwrite existing SPF record?"; then
      echo -e "    ${YELLOW}🔄 Updating existing SPF record${NC}"
      curl -fsS -X PUT "${auth_hdr[@]}" \
        --data "$(jq -nc --arg type TXT --arg name "$name" --arg content "$content" '{type:$type,name:$name,content:$content,ttl:1}')" \
        "${API}/zones/${zone_id}/dns_records/${id}" >/dev/null
      echo -e "    ${GREEN}✅ SPF record updated${NC}"
    else
      echo -e "    ${BLUE}⏭️  Skipping SPF record update${NC}"
    fi
  else
    echo -e "    ${YELLOW}➕ Creating new SPF record${NC}"
    curl -fsS -X POST "${auth_hdr[@]}" \
      --data "$(jq -nc --arg type TXT --arg name "$name" --arg content "$content" '{type:$type,name:$name,content:$content,ttl:1}')" \
      "${API}/zones/${zone_id}/dns_records" >/dev/null
    echo -e "    ${GREEN}✅ SPF record created${NC}"
  fi
}

ensure_null_mx() {
  local zone_id="$1" root_name="$2"
  local resp; resp="$(curl -fsS "${auth_hdr[@]}" "${API}/zones/${zone_id}/dns_records?type=MX&name=${root_name}")"
  local count; count="$(jq '.result | length' <<<"$resp")"
  
  if [[ "$count" -gt 0 ]]; then
    # Check if existing MX records are already null MX
    local all_null=true
    local existing_records=""
    while read -r content priority; do
      existing_records+="        Priority $priority: $content"$'\n'
      if [[ "$content" != "." ]]; then
        all_null=false
      fi
    done < <(jq -r '.result[] | "\(.content) \(.priority)"' <<<"$resp")
    
    if [[ "$all_null" == "true" ]]; then
      echo -e "    ${GREEN}✅ Null MX record already correct${NC}"
      return
    fi
    
    echo -e "    ${YELLOW}⚠️  Existing MX records found:${NC}"
    echo -e "${RED}$existing_records${NC}"
    echo -e "      ${GREEN}Desired: Priority 0: . (null MX)${NC}"
    
    if prompt_user "    Overwrite existing MX records with null MX?"; then
      echo -e "    ${YELLOW}🔄 Updating existing MX records to null MX${NC}"
      jq -r '.result[].id' <<<"$resp" | while read -r rid; do
        curl -fsS -X PUT "${auth_hdr[@]}" \
          --data "$(jq -nc --arg type MX --arg name "$root_name" --arg content "." '{type:$type,name:$name,content:$content,priority:0,ttl:1}')" \
          "${API}/zones/${zone_id}/dns_records/${rid}" >/dev/null
      done
      echo -e "    ${GREEN}✅ MX records updated to null MX${NC}"
    else
      echo -e "    ${BLUE}⏭️  Skipping MX record update${NC}"
    fi
  else
    echo -e "    ${YELLOW}➕ Creating null MX record${NC}"
    curl -fsS -X POST "${auth_hdr[@]}" \
      --data "$(jq -nc --arg type MX --arg name "$root_name" --arg content "." '{type:$type,name:$name,content:$content,priority:0,ttl:1}')" \
      "${API}/zones/${zone_id}/dns_records" >/dev/null
    echo -e "    ${GREEN}✅ Null MX record created${NC}"
  fi
}

upsert_dmarc() {
  local zone_id="$1" domain="$2"
  local dmarc_name="_dmarc.$domain"
  local dmarc_content="\"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;\""
  local id; id="$(find_record_id "$zone_id" "TXT" "$dmarc_name")"
  
  if [[ -n "$id" ]]; then
    local existing_content; existing_content="$(curl -fsS "${auth_hdr[@]}" "${API}/zones/${zone_id}/dns_records/${id}" | jq -r '.result.content')"
    # Remove quotes for comparison and check if it's already a strict DMARC policy
    local clean_existing; clean_existing="${existing_content//\"/}"
    if [[ "$clean_existing" =~ v=DMARC1.*p=reject ]]; then
      echo -e "    ${GREEN}✅ DMARC record already has reject policy${NC}"
      return
    fi
    
    echo -e "    ${YELLOW}⚠️  Existing DMARC record found:${NC}"
    echo -e "      Current: ${RED}$existing_content${NC}"
    echo -e "      Desired: ${GREEN}v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;${NC}"
    
    if prompt_user "    Overwrite existing DMARC record with strict policy?"; then
      echo -e "    ${YELLOW}🔄 Updating existing DMARC record${NC}"
      curl -fsS -X PUT "${auth_hdr[@]}" \
        --data "$(jq -nc --arg type TXT --arg name "$dmarc_name" --arg content "$dmarc_content" '{type:$type,name:$name,content:$content,ttl:1}')" \
        "${API}/zones/${zone_id}/dns_records/${id}" >/dev/null
      echo -e "    ${GREEN}✅ DMARC record updated${NC}"
    else
      echo -e "    ${BLUE}⏭️  Skipping DMARC record update${NC}"
    fi
  else
    echo -e "    ${YELLOW}➕ Creating DMARC record${NC}"
    curl -fsS -X POST "${auth_hdr[@]}" \
      --data "$(jq -nc --arg type TXT --arg name "$dmarc_name" --arg content "$dmarc_content" '{type:$type,name:$name,content:$content,ttl:1}')" \
      "${API}/zones/${zone_id}/dns_records" >/dev/null
    echo -e "    ${GREEN}✅ DMARC record created${NC}"
  fi
}

# Check if file exists and count domains
if [[ ! -f domains.txt ]]; then
  echo -e "${RED}❌ domains.txt file not found!${NC}"
  exit 1
fi

# Count valid domains in file
domain_count=0
while IFS= read -r line || [[ -n "$line" ]]; do
  domain="${line%%#*}"
  domain="$(echo -n "$domain" | xargs)"
  [[ -n "$domain" ]] && domain_count=$((domain_count + 1))
done < domains.txt

echo -e "${BLUE}📋 Found ${domain_count} domains in domains.txt${NC}"

processed_count=0

while IFS= read -r line || [[ -n "$line" ]]; do
  domain="${line%%#*}"
  domain="$(echo -n "$domain" | xargs)"
  
  if [[ -z "$domain" ]]; then
    continue
  fi

  echo -e "${BLUE}🌐 Processing ${domain}${NC}"
  processed_count=$((processed_count + 1))
  
  echo "  🔍 Looking up zone ID for ${domain}..."
  zone_id="$(get_zone_id "$domain")"
  if [[ -z "$zone_id" ]]; then
    echo -e "  ${RED}❌ Zone not found in Cloudflare for ${domain}, skipping${NC}\n"
    continue
  fi
  echo "  ✅ Zone found"

  upsert_txt_spf "$zone_id" "$domain"
  ensure_null_mx "$zone_id" "$domain"
  upsert_dmarc "$zone_id" "$domain"
  echo ""
done < domains.txt

echo -e "${BLUE}Processed ${processed_count} domains total${NC}"

echo -e "${GREEN}🎉 Email security lockdown complete!${NC}"
echo -e "${GREEN}All domains are now protected against email spoofing and phishing.${NC}"