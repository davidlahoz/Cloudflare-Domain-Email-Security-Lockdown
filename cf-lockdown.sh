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

get_all_records() {
  local zone_id="$1" type="$2" name="$3"
  curl -fsS "${auth_hdr[@]}" \
    "${API}/zones/${zone_id}/dns_records?type=${type}&name=${name}" \
  | jq -r '.result[] | "\(.id) \(.content) \(.priority // "N/A")"'
}

delete_record() {
  local zone_id="$1" record_id="$2"
  curl -fsS -X DELETE "${auth_hdr[@]}" \
    "${API}/zones/${zone_id}/dns_records/${record_id}" >/dev/null
}

prompt_user() {
  local prompt="$1"
  local response
  echo -n "$prompt (y/N): "
  read -r response </dev/tty
  [[ "$response" =~ ^[Yy]$ ]]
}

upsert_txt_spf() {
  local zone_id="$1" record_name="$2" domain="$3"
  local content='v=spf1 -all'
  
  # For root domain (@), use the actual domain name for API calls
  local api_name="$domain"
  if [[ "$record_name" != "@" ]]; then
    api_name="${record_name}.${domain}"
  fi

  # Check if a TXT record exists using the full domain name
  local txt_record_id
  txt_record_id="$(find_record_id "$zone_id" "TXT" "$api_name")"
  if [[ -n "$txt_record_id" ]]; then
    # Get the content of the existing TXT record
    local existing_content
    existing_content="$(curl -fsS "${auth_hdr[@]}" "${API}/zones/${zone_id}/dns_records/${txt_record_id}" | jq -r '.result.content // empty')"
    local clean_content="${existing_content//\"/}"
    if [[ "$clean_content" == "v=spf1 -all" ]]; then
      echo -e "    ${GREEN}✅ SPF record already correct${NC}"
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain TXT: Already correct - v=spf1 -all" >> "$LOG_FILE"
      return
    else
      # It's a TXT record for @, but not the correct value
      echo -e "    ${YELLOW}⚠️  Existing TXT record for @ found:${NC}"
      echo -e "      Current: ${RED}$existing_content${NC}"
      echo -e "      Desired: ${GREEN}v=spf1 -all${NC}"
      if prompt_user "    Overwrite existing TXT record for @ with SPF?"; then
        echo -e "    ${YELLOW}🔄 Updating existing TXT record to SPF${NC}"
        local clean_content='"v=spf1 -all"'
        jq -nc --arg type TXT --arg name "@" --arg content "$clean_content" --argjson ttl 1 '{type:$type,name:$name,content:$content,ttl:$ttl}' >&2
        if curl -fsS -X PUT "${auth_hdr[@]}" \
          --data "$(jq -nc --arg type TXT --arg name "@" --arg content "$clean_content" --argjson ttl 1 '{type:$type,name:$name,content:$content,ttl:$ttl}')" \
          "${API}/zones/${zone_id}/dns_records/${txt_record_id}" >/dev/null; then
          echo -e "    ${GREEN}✅ SPF record updated${NC}"
          echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain TXT: UPDATED - Previous: $existing_content | New: v=spf1 -all" >> "$LOG_FILE"
        else
          echo -e "    ${RED}❌ Failed to update SPF record${NC}"
          echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain TXT: FAILED to update SPF" >> "$LOG_FILE"
          return 1
        fi
      else
        echo -e "    ${BLUE}⏭️  Skipping SPF record update${NC}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain TXT: SKIPPED by user - Current: $existing_content" >> "$LOG_FILE"
        return 2
      fi
      return
    fi
  fi

  # No TXT record found, create new SPF record
  echo -e "    ${YELLOW}➕ Creating new SPF record${NC}"
  local clean_content='"v=spf1 -all"'
  jq -nc --arg type TXT --arg name "@" --arg content "$clean_content" --argjson ttl 1 '{type:$type,name:$name,content:$content,ttl:$ttl}' >&2
  if curl -fsS -X POST "${auth_hdr[@]}" \
    --data "$(jq -nc --arg type TXT --arg name "@" --arg content "$clean_content" --argjson ttl 1 '{type:$type,name:$name,content:$content,ttl:$ttl}')" \
    "${API}/zones/${zone_id}/dns_records" >/dev/null; then
    echo -e "    ${GREEN}✅ SPF record created${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain TXT: CREATED - New: v=spf1 -all" >> "$LOG_FILE"
  else
    echo -e "    ${RED}❌ Failed to create SPF record${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain TXT: FAILED to create SPF" >> "$LOG_FILE"
    return 1
  fi
}

ensure_null_mx() {
  local zone_id="$1" record_name="$2" domain="$3"
  
  # For root domain (@), use the actual domain name for API calls
  local api_name="$domain"
  if [[ "$record_name" != "@" ]]; then
    api_name="${record_name}.${domain}"
  fi
  
  # First, get ALL MX records for the domain
  local mx_records
  mx_records="$(get_all_records "$zone_id" "MX" "$api_name")"
  
  # Check if we already have the correct null MX record
  local has_correct_mx=false
  local other_mx_records=()
  
  while IFS= read -r record_line; do
    [[ -z "$record_line" ]] && continue
    local record_id content priority
    read -r record_id content priority <<< "$record_line"
    
    if [[ "$content" == "." && "$priority" == "0" ]]; then
      has_correct_mx=true
    else
      other_mx_records+=("$record_id:$content:$priority")
    fi
  done <<< "$mx_records"
  
  if [[ "$has_correct_mx" == "true" && ${#other_mx_records[@]} -eq 0 ]]; then
    echo -e "    ${GREEN}✅ Null MX record already correct${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain MX: Already correct - Priority 0: ." >> "$LOG_FILE"
    return
  fi
  
  # If we have other MX records, ask user to delete them
  if [[ ${#other_mx_records[@]} -gt 0 ]]; then
    echo -e "    ${YELLOW}⚠️  Found ${#other_mx_records[@]} existing MX record(s):${NC}"
    for record_info in "${other_mx_records[@]}"; do
      IFS=':' read -r record_id content priority <<< "$record_info"
      echo -e "      ${RED}Priority $priority: $content${NC}"
    done
    echo -e "      Desired: ${GREEN}Priority 0: . (null MX)${NC}"
    if prompt_user "    Delete existing MX records and create null MX?"; then
      echo -e "    ${YELLOW}🗑️  Deleting existing MX records${NC}"
      for record_info in "${other_mx_records[@]}"; do
        IFS=':' read -r record_id content priority <<< "$record_info"
        if delete_record "$zone_id" "$record_id"; then
          echo -e "    ${GREEN}✅ Deleted MX record: Priority $priority: $content${NC}"
          echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain MX: DELETED - Priority $priority: $content" >> "$LOG_FILE"
        else
          echo -e "    ${RED}❌ Failed to delete MX record: Priority $priority: $content${NC}"
          echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain MX: FAILED to delete - Priority $priority: $content" >> "$LOG_FILE"
          return 1
        fi
      done
    else
      echo -e "    ${BLUE}⏭️  Skipping MX record changes${NC}"
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain MX: SKIPPED by user" >> "$LOG_FILE"
      return 2
    fi
  fi
  
  # Create null MX record if we don't have the correct one
  if [[ "$has_correct_mx" == "false" ]]; then
    echo -e "    ${YELLOW}➕ Creating null MX record${NC}"
    if curl -fsS -X POST "${auth_hdr[@]}" \
      --data "$(jq -nc --arg type MX --arg name "@" --arg content "." --argjson priority 0 --argjson ttl 1 '{type:$type,name:$name,content:$content,priority:$priority,ttl:$ttl}')" \
      "${API}/zones/${zone_id}/dns_records" >/dev/null; then
      echo -e "    ${GREEN}✅ Null MX record created${NC}"
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain MX: CREATED - New: Priority 0: ." >> "$LOG_FILE"
    else
      echo -e "    ${RED}❌ Failed to create null MX record${NC}"
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain MX: FAILED to create null MX" >> "$LOG_FILE"
      return 1
    fi
  fi
}

ensure_null_mx_old() {
  local zone_id="$1" record_name="$2" domain="$3"
  # Check if an MX record with name "@" exists using find_record_id
  local mx_record_id
  mx_record_id="$(find_record_id "$zone_id" "MX" "$record_name")"
  if [[ -n "$mx_record_id" ]]; then
    # Get the content and priority of the existing MX record
    local existing_content existing_priority
    existing_content="$(curl -fsS "${auth_hdr[@]}" "${API}/zones/${zone_id}/dns_records/${mx_record_id}" | jq -r '.result.content // empty')"
    existing_priority="$(curl -fsS "${auth_hdr[@]}" "${API}/zones/${zone_id}/dns_records/${mx_record_id}" | jq -r '.result.priority // empty')"
    if [[ "$existing_content" == "." && "$existing_priority" == "0" ]]; then
      echo -e "    ${GREEN}✅ Null MX record already correct${NC}"
      echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain MX: Already correct - Priority 0: ." >> "$LOG_FILE"
      return
    else
      echo -e "    ${YELLOW}⚠️  Existing MX record for @ found:${NC}"
      echo -e "      Current: ${RED}Priority $existing_priority: $existing_content${NC}"
      echo -e "      Desired: ${GREEN}Priority 0: . (null MX)${NC}"
      if prompt_user "    Overwrite existing MX record for @ with null MX?"; then
        echo -e "    ${YELLOW}🔄 Updating existing MX record to null MX${NC}"
        jq -nc --arg type MX --arg name "@" --arg content "." --argjson priority 0 '{type:$type,name:$name,content:$content,priority:$priority,ttl:1}' >&2
        if curl -fsS -X PUT "${auth_hdr[@]}" \
          --data "$(jq -nc --arg type MX --arg name "@" --arg content "." --argjson priority 0 '{type:$type,name:$name,content:$content,priority:$priority,ttl:1}')" \
          "${API}/zones/${zone_id}/dns_records/${mx_record_id}" >/dev/null; then
          echo -e "    ${GREEN}✅ Null MX record updated${NC}"
          echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain MX: UPDATED - Previous: Priority $existing_priority: $existing_content | New: Priority 0: ." >> "$LOG_FILE"
        else
          echo -e "    ${RED}❌ Failed to update MX record${NC}"
          echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain MX: FAILED to update MX" >> "$LOG_FILE"
          return 1
        fi
      else
        echo -e "    ${BLUE}⏭️  Skipping MX record update${NC}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain MX: SKIPPED by user - Current: Priority $existing_priority: $existing_content" >> "$LOG_FILE"
        return 2
      fi
      return
    fi
  fi

  # No MX record for @ found, create null MX
  echo -e "    ${YELLOW}➕ Creating null MX record${NC}"
  jq -nc --arg type MX --arg name "@" --arg content "." --argjson priority 0 '{type:$type,name:$name,content:$content,priority:$priority,ttl:1}' >&2
  if curl -fsS -X POST "${auth_hdr[@]}" \
    --data "$(jq -nc --arg type MX --arg name "@" --arg content "." --argjson priority 0 '{type:$type,name:$name,content:$content,priority:$priority,ttl:1}')" \
    "${API}/zones/${zone_id}/dns_records" >/dev/null; then
    echo -e "    ${GREEN}✅ Null MX record created${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain MX: CREATED - New: Priority 0: ." >> "$LOG_FILE"
  else
    echo -e "    ${RED}❌ Failed to create null MX record${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $domain MX: FAILED to create null MX" >> "$LOG_FILE"
    return 1
  fi
}

upsert_dmarc() {
  local zone_id="$1" domain="$2"
  local dmarc_name="_dmarc"
  local dmarc_content='v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;'
  local dmarc_fqdn="${dmarc_name}.$domain"
  local resp; resp="$(curl -fsS "${auth_hdr[@]}" "${API}/zones/${zone_id}/dns_records?type=TXT&name=${dmarc_fqdn}")"
  local found_correct_dmarc=false
  local found_dmarc_id=""
  local found_dmarc_content=""
  local found_dmarc=false
  local desired_clean="v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;"
  # Iterate all TXT records for _dmarc.domain
  while read -r id content_val; do
    local clean_content="${content_val//\"/}"
    if [[ "$clean_content" == "$desired_clean" ]]; then
      found_correct_dmarc=true
      break
    else
      found_dmarc_id="$id"
      found_dmarc_content="$content_val"
      found_dmarc=true
    fi
  done < <(echo "$resp" | jq -r '.result[] | "\(.id) \(.content)"')

  if [[ "$found_correct_dmarc" == "true" ]]; then
    echo -e "    ${GREEN}✅ DMARC record already correct${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ${dmarc_name}.$domain TXT: Already correct - $desired_clean" >> "$LOG_FILE"
    return
  fi

  if [[ "$found_dmarc" == "true" && -n "$found_dmarc_id" ]]; then
    echo -e "    ${YELLOW}⚠️  Existing DMARC record found:${NC}"
    echo -e "      Current: ${RED}$found_dmarc_content${NC}"
    echo -e "      Desired: ${GREEN}v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;${NC}"
    if prompt_user "    Overwrite existing DMARC record with strict policy?"; then
      echo -e "    ${YELLOW}🔄 Updating existing DMARC record${NC}"
      echo "DEBUG Payload:" >&2
      local clean_dmarc='"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;"'
      jq -nc --arg type TXT --arg name "$dmarc_name" --arg zone "$domain" --arg content "$clean_dmarc" --argjson ttl 1 '{type:$type,name:($name + "." + $zone),content:$content,ttl:$ttl}' >&2
      if curl -fsS -X PUT "${auth_hdr[@]}" \
        --data "$(jq -nc --arg type TXT --arg name "$dmarc_name" --arg zone "$domain" --arg content "$clean_dmarc" --argjson ttl 1 '{type:$type,name:($name + "." + $zone),content:$content,ttl:$ttl}')" \
        "${API}/zones/${zone_id}/dns_records/${found_dmarc_id}" >/dev/null; then
        echo -e "    ${GREEN}✅ DMARC record updated${NC}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ${dmarc_name}.$domain TXT: UPDATED - Previous: $found_dmarc_content | New: v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;" >> "$LOG_FILE"
      else
        echo -e "    ${RED}❌ Failed to update DMARC record${NC}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ${dmarc_name}.$domain TXT: FAILED to update DMARC" >> "$LOG_FILE"
        return 1
      fi
    else
      echo -e "    ${BLUE}⏭️  Skipping DMARC record update${NC}"
      echo "$(date '+%Y-%m-%d %H:%M:%S') - ${dmarc_name}.$domain TXT: SKIPPED by user - Current: $found_dmarc_content" >> "$LOG_FILE"
      return 2
    fi
    return
  fi

  # No DMARC record found, create new
  echo -e "    ${YELLOW}➕ Creating DMARC record${NC}"
  echo "DEBUG Payload:" >&2
  local clean_dmarc='"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;"'
  jq -nc --arg type TXT --arg name "$dmarc_name" --arg zone "$domain" --arg content "$clean_dmarc" --argjson ttl 1 '{type:$type,name:($name + "." + $zone),content:$content,ttl:$ttl}' >&2
  if curl -fsS -X POST "${auth_hdr[@]}" \
    --data "$(jq -nc --arg type TXT --arg name "$dmarc_name" --arg zone "$domain" --arg content "$clean_dmarc" --argjson ttl 1 '{type:$type,name:($name + "." + $zone),content:$content,ttl:$ttl}')" \
    "${API}/zones/${zone_id}/dns_records" >/dev/null; then
    echo -e "    ${GREEN}✅ DMARC record created${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ${dmarc_name}.$domain TXT: CREATED - New: v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;" >> "$LOG_FILE"
  else
    echo -e "    ${RED}❌ Failed to create DMARC record${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ${dmarc_name}.$domain TXT: FAILED to create DMARC" >> "$LOG_FILE"
    return 1
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

  record_name="@"

  upsert_txt_spf "$zone_id" "$record_name" "$domain"
  spf_exit_code=$?
  if [[ $spf_exit_code -eq 2 ]]; then
    domain_skipped=true
  elif [[ $spf_exit_code -ne 0 ]]; then
    domain_success=false
  fi

  ensure_null_mx "$zone_id" "$record_name" "$domain"
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