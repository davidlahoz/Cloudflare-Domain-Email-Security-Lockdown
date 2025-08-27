#!/usr/bin/env bash
set -euo pipefail

# Cloudflare Domain Email Security Lockdown
# Purpose: For each domain in domains.txt, set SPF "v=spf1 -all" , DMARC rule and a null MX.
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

# Initialize log file
LOG_FILE="cf-lockdown-$(date +%Y%m%d-%H%M%S).log"
echo "$(date '+%Y-%m-%d %H:%M:%S') - Cloudflare Domain Email Security Lockdown Started" > "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - Log file: $LOG_FILE" >> "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - ===========================================" >> "$LOG_FILE"
echo ""
echo -e "${BLUE}📝 Logging changes to: ${LOG_FILE}${NC}"

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
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $name TXT: Already correct - $existing_content" >> "$LOG_FILE"
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
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $name TXT: UPDATED - Previous: $existing_content | New: v=spf1 -all" >> "$LOG_FILE"
    else
      echo -e "    ${BLUE}⏭️  Skipping SPF record update${NC}"
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $name TXT: SKIPPED by user - Current: $existing_content" >> "$LOG_FILE"
      return 2
    fi
  else
    echo -e "    ${YELLOW}➕ Creating new SPF record${NC}"
    curl -fsS -X POST "${auth_hdr[@]}" \
      --data "$(jq -nc --arg type TXT --arg name "$name" --arg content "$content" '{type:$type,name:$name,content:$content,ttl:1}')" \
      "${API}/zones/${zone_id}/dns_records" >/dev/null
    echo -e "    ${GREEN}✅ SPF record created${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $name TXT: CREATED - New: v=spf1 -all" >> "$LOG_FILE"
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
    local log_existing=""
    while read -r content priority; do
      existing_records+="        Priority $priority: $content"$'\n'
      log_existing+="Priority $priority: $content; "
      if [[ "$content" != "." ]]; then
        all_null=false
      fi
    done < <(jq -r '.result[] | "\(.content) \(.priority)"' <<<"$resp")
    
    if [[ "$all_null" == "true" ]]; then
      echo -e "    ${GREEN}✅ Null MX record already correct${NC}"
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $root_name MX: Already correct - ${log_existing%%; }" >> "$LOG_FILE"
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
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $root_name MX: UPDATED - Previous: ${log_existing%%; } | New: Priority 0: ." >> "$LOG_FILE"
    else
      echo -e "    ${BLUE}⏭️  Skipping MX record update${NC}"
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $root_name MX: SKIPPED by user - Current: ${log_existing%%; }" >> "$LOG_FILE"
      return 2
    fi
  else
    echo -e "    ${YELLOW}➕ Creating null MX record${NC}"
    curl -fsS -X POST "${auth_hdr[@]}" \
      --data "$(jq -nc --arg type MX --arg name "$root_name" --arg content "." '{type:$type,name:$name,content:$content,priority:0,ttl:1}')" \
      "${API}/zones/${zone_id}/dns_records" >/dev/null
    echo -e "    ${GREEN}✅ Null MX record created${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $root_name MX: CREATED - New: Priority 0: ." >> "$LOG_FILE"
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
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $dmarc_name TXT: Already correct - $existing_content" >> "$LOG_FILE"
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
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $dmarc_name TXT: UPDATED - Previous: $existing_content | New: v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;" >> "$LOG_FILE"
    else
      echo -e "    ${BLUE}⏭️  Skipping DMARC record update${NC}"
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $dmarc_name TXT: SKIPPED by user - Current: $existing_content" >> "$LOG_FILE"
      return 2
    fi
  else
    echo -e "    ${YELLOW}➕ Creating DMARC record${NC}"
    curl -fsS -X POST "${auth_hdr[@]}" \
      --data "$(jq -nc --arg type TXT --arg name "$dmarc_name" --arg content "$dmarc_content" '{type:$type,name:$name,content:$content,ttl:1}')" \
      "${API}/zones/${zone_id}/dns_records" >/dev/null
    echo -e "    ${GREEN}✅ DMARC record created${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $dmarc_name TXT: CREATED - New: v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;" >> "$LOG_FILE"
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
  domain="$(echo -n "$domain" | tr -d '\r' | xargs)"
  
  # Skip empty lines or lines with editor artifacts
  [[ -z "$domain" ]] && continue
  [[ "$domain" =~ "No newline" ]] && continue
  [[ "$domain" =~ "at end of file" ]] && continue
  # Skip lines that don't look like domains (must contain at least one dot)
  [[ ! "$domain" =~ \. ]] && continue
  
  domain_count=$((domain_count + 1))
done < domains.txt

echo -e "${BLUE}📋 Found ${domain_count} domains in domains.txt${NC}"

processed_count=0
successful_domains=()
failed_domains=()
skipped_domains=()

while IFS= read -r line || [[ -n "$line" ]]; do
  domain="${line%%#*}"
  domain="$(echo -n "$domain" | tr -d '\r' | xargs)"
  
  # Skip empty lines or lines with editor artifacts
  [[ -z "$domain" ]] && continue
  [[ "$domain" =~ "No newline" ]] && continue
  [[ "$domain" =~ "at end of file" ]] && continue
  # Skip lines that don't look like domains (must contain at least one dot)
  [[ ! "$domain" =~ \. ]] && continue

  echo -e "${BLUE}🌐 Processing ${domain}${NC}"
  processed_count=$((processed_count + 1))
  
  echo "  🔍 Looking up zone ID for ${domain}..."
  zone_id="$(get_zone_id "$domain")"
  if [[ -z "$zone_id" ]]; then
    echo -e "  ${RED}❌ Zone not found in Cloudflare for ${domain}, skipping${NC}\n"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain: ZONE NOT FOUND - Domain not managed by Cloudflare or API token lacks access" >> "$LOG_FILE"
    failed_domains+=("$domain (zone not found)")
    continue
  fi
  echo "  ✅ Zone found"
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain: PROCESSING STARTED" >> "$LOG_FILE"

  # Track success/failure for each domain
  domain_success=true
  domain_skipped=false
  
  # Temporarily disable exit on error for these function calls
  set +e
  
  upsert_txt_spf "$zone_id" "$domain"
  spf_exit_code=$?
  if [[ $spf_exit_code -eq 2 ]]; then
    domain_skipped=true
  elif [[ $spf_exit_code -ne 0 ]]; then
    domain_success=false
  fi
  
  ensure_null_mx "$zone_id" "$domain"
  mx_exit_code=$?
  if [[ $mx_exit_code -eq 2 ]]; then
    domain_skipped=true
  elif [[ $mx_exit_code -ne 0 ]]; then
    domain_success=false
  fi
  
  upsert_dmarc "$zone_id" "$domain"
  dmarc_exit_code=$?
  if [[ $dmarc_exit_code -eq 2 ]]; then
    domain_skipped=true
  elif [[ $dmarc_exit_code -ne 0 ]]; then
    domain_success=false
  fi
  
  # Re-enable exit on error
  set -e
  
  if [[ "$domain_skipped" == "true" ]]; then
    skipped_domains+=("$domain (user skipped some records)")
  elif [[ "$domain_success" == "true" ]]; then
    successful_domains+=("$domain")
  else
    failed_domains+=("$domain (configuration errors)")
  fi
  
  echo ""
done < domains.txt

echo -e "${BLUE}Processed ${processed_count} domains total${NC}"

# Summary report
echo ""
echo -e "${BLUE}📊 SUMMARY REPORT${NC}"
echo -e "${BLUE}=================${NC}"

if [[ ${#successful_domains[@]} -gt 0 ]]; then
  echo -e "\n${GREEN}✅ Successfully configured (${#successful_domains[@]} domains):${NC}"
  for domain in "${successful_domains[@]}"; do
    echo -e "  ${GREEN}• $domain${NC}"
  done
fi

if [[ ${#failed_domains[@]} -gt 0 ]]; then
  echo -e "\n${RED}❌ Failed or need manual review (${#failed_domains[@]} domains):${NC}"
  for domain in "${failed_domains[@]}"; do
    echo -e "  ${RED}• $domain${NC}"
  done
fi

if [[ ${#skipped_domains[@]} -gt 0 ]]; then
  echo -e "\n${YELLOW}⏭️  User skipped (${#skipped_domains[@]} domains):${NC}"
  for domain in "${skipped_domains[@]}"; do
    echo -e "  ${YELLOW}• $domain${NC}"
  done
fi

echo ""
if [[ ${#successful_domains[@]} -eq $processed_count ]]; then
  echo -e "${GREEN}🎉 Email security lockdown complete!${NC}"
  echo -e "${GREEN}All domains are now protected against email spoofing and phishing.${NC}"
elif [[ ${#failed_domains[@]} -gt 0 ]]; then
  echo -e "${YELLOW}⚠️  Email security lockdown completed with some failures.${NC}"
  echo -e "${YELLOW}Please review failed domains and configure manually if needed.${NC}"
else
  echo -e "${BLUE}ℹ️  Email security lockdown completed.${NC}"
  echo -e "${BLUE}Some domains were skipped by user choice.${NC}"
fi

# Final log summary
echo "" >> "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - ===========================================" >> "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - FINAL SUMMARY:" >> "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - Total domains processed: $processed_count" >> "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - Successfully configured: ${#successful_domains[@]}" >> "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - Failed or zone not found: ${#failed_domains[@]}" >> "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - Skipped by user: ${#skipped_domains[@]}" >> "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - Email security lockdown completed" >> "$LOG_FILE"

echo -e "\n${BLUE}📝 Complete log saved to: ${LOG_FILE}${NC}"