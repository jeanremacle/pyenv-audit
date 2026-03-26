#!/usr/bin/env bash
# pyenv-audit.sh — Audit all pyenv Python versions for known vulnerabilities.
#
# Uses globally installed tools (via uv tool / pipx):
#   - pip-audit: vulnerability scanning
#   - cvss (Python lib): CVSS score computation
#   - jq, curl: OSV enrichment
#
# Usage:
#   pyenv-audit.sh                          # audit, show HIGH+ only
#   pyenv-audit.sh --severity all           # show all severities
#   pyenv-audit.sh --severity moderate      # show MODERATE+
#   pyenv-audit.sh --version 3.12.6         # audit only one pyenv version
#   pyenv-audit.sh --fix                    # generate and run pip upgrade commands
#   pyenv-audit.sh --fix --dry-run          # show upgrade commands without running
#   pyenv-audit.sh --help                   # show this help

set -euo pipefail

PYENV_ROOT="${PYENV_ROOT:-$HOME/.pyenv}"
MODE="audit"
FILTER_VERSION=""
SEVERITY_THRESHOLD="HIGH"  # HIGH (default), MODERATE, LOW, ALL

# --- Argument parsing -----------------------------------------------------------
PREV_ARG=""
for arg in "$@"; do
  case "$arg" in
    --fix)      MODE="fix" ;;
    --dry-run)  MODE="dry-run" ;;
    --help|-h)
      sed -n '2,16s/^# //p' "$0"
      exit 0
      ;;
    --version|--severity)
      ;; # value captured below
    *)
      if [[ "${PREV_ARG:-}" == "--version" ]]; then
        FILTER_VERSION="$arg"
      elif [[ "${PREV_ARG:-}" == "--severity" ]]; then
        SEVERITY_THRESHOLD=$(echo "$arg" | tr '[:lower:]' '[:upper:]')
        if [[ ! "$SEVERITY_THRESHOLD" =~ ^(ALL|LOW|MODERATE|HIGH|CRITICAL)$ ]]; then
          echo "ERROR: --severity must be one of: all, low, moderate, high, critical" >&2
          exit 1
        fi
      else
        echo "Unknown option: $arg" >&2
        exit 1
      fi
      ;;
  esac
  PREV_ARG="$arg"
done

# --- Dependency check -----------------------------------------------------------
PIP_AUDIT_BIN=""

for candidate in \
  "$HOME/.local/bin/pip-audit" \
  "$(command -v pip-audit 2>/dev/null || true)"; do
  if [ -n "$candidate" ] && [ -x "$candidate" ]; then
    PIP_AUDIT_BIN="$candidate"
    break
  fi
done

if [ -z "$PIP_AUDIT_BIN" ]; then
  echo "ERROR: pip-audit not found. Install with: uv tool install pip-audit" >&2
  exit 1
fi

CVSS_PYTHON=""
if [ -x "$HOME/.local/share/uv/tools/cvss/bin/python3" ]; then
  CVSS_PYTHON="$HOME/.local/share/uv/tools/cvss/bin/python3"
fi

for cmd in jq curl; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' is required but not found in PATH." >&2
    exit 1
  fi
done

# --- Color helpers --------------------------------------------------------------
if [ -t 1 ]; then
  RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; DIM=''; RESET=''
fi

# --- Severity helpers -----------------------------------------------------------
# Returns a numeric severity level: CRITICAL=4, HIGH=3, MODERATE=2, LOW=1, UNKNOWN=0
severity_to_num() {
  case "$(echo "$1" | tr '[:lower:]' '[:upper:]')" in
    CRITICAL)       echo 4 ;;
    HIGH)           echo 3 ;;
    MODERATE|MEDIUM) echo 2 ;;
    LOW)            echo 1 ;;
    *)              echo 0 ;;
  esac
}

threshold_num() {
  case "$SEVERITY_THRESHOLD" in
    ALL)      echo 0 ;;
    LOW)      echo 1 ;;
    MODERATE) echo 2 ;;
    HIGH)     echo 3 ;;
    CRITICAL) echo 4 ;;
  esac
}

severity_color() {
  case "$(echo "$1" | tr '[:lower:]' '[:upper:]')" in
    CRITICAL)       echo -ne "${RED}${BOLD}" ;;
    HIGH)           echo -ne "${RED}" ;;
    MODERATE|MEDIUM) echo -ne "${YELLOW}" ;;
    LOW)            echo -ne "${GREEN}" ;;
    *)              echo -ne "${DIM}" ;;
  esac
}

# Compute severity from CVSS score (numeric)
score_to_severity() {
  local score="$1"
  if [ "$score" = "N/A" ] || [ -z "$score" ]; then
    echo "UNKNOWN"
    return
  fi
  # Use awk for float comparison (portable)
  awk -v s="$score" 'BEGIN {
    if (s >= 9.0) print "CRITICAL"
    else if (s >= 7.0) print "HIGH"
    else if (s >= 4.0) print "MODERATE"
    else if (s >= 0.1) print "LOW"
    else print "UNKNOWN"
  }'
}

# --- CVSS score calculators -----------------------------------------------------
cvss3_base_score() {
  local vector="$1"
  if [ -n "$CVSS_PYTHON" ]; then
    "$CVSS_PYTHON" -c "
from cvss import CVSS3
try:
    v = CVSS3('$vector')
    print(v.base_score)
except Exception:
    print('N/A')
" 2>/dev/null || echo "N/A"
  else
    echo "N/A"
  fi
}

cvss4_base_score() {
  local vector="$1"
  if [ -n "$CVSS_PYTHON" ]; then
    "$CVSS_PYTHON" -c "
from cvss import CVSS4
try:
    v = CVSS4('$vector')
    print(v.base_score)
except Exception:
    print('N/A')
" 2>/dev/null || echo "N/A"
  else
    echo "N/A"
  fi
}

# --- OSV lookup ----------------------------------------------------------------
osv_lookup() {
  local vuln_id="$1"
  curl -sf --max-time 10 "https://api.osv.dev/v1/vulns/${vuln_id}" 2>/dev/null || echo "{}"
}

enrich_vuln() {
  local vuln_id="$1"
  local aliases="$2"

  local all_ids="${vuln_id}"
  if [ -n "$aliases" ]; then
    all_ids="${vuln_id} ${aliases}"
  fi

  for id in $all_ids; do
    local response
    response=$(osv_lookup "$id")
    local has_severity
    has_severity=$(echo "$response" | jq -e '.severity // empty' 2>/dev/null || true)
    if [ -n "$has_severity" ]; then
      echo "$response"
      return 0
    fi
  done

  osv_lookup "$vuln_id"
}

# --- Per-version audit ----------------------------------------------------------
audit_version() {
  local pip_bin="$1"
  local ver_dir
  ver_dir=$(dirname "$(dirname "$pip_bin")")
  local ver_name
  ver_name=$(basename "$ver_dir")

  # Derive site-packages path (BSD grep compatible)
  local py_major_minor
  py_major_minor=$("$pip_bin" --version 2>/dev/null | sed -n 's/.*python \([0-9]*\.[0-9]*\).*/\1/p' || true)
  local site_packages="${ver_dir}/lib/python${py_major_minor}/site-packages"

  echo -e "\n${BOLD}${CYAN}======================================================================${RESET}"
  echo -e "${BOLD}${CYAN}  Python $ver_name${RESET}"
  echo -e "${BOLD}${CYAN}======================================================================${RESET}"

  if [ ! -d "$site_packages" ]; then
    echo -e "  ${RED}site-packages not found at ${site_packages}, skipping.${RESET}"
    return 1
  fi

  local pkg_count
  pkg_count=$(find "$site_packages" -maxdepth 1 -name '*.dist-info' -type d 2>/dev/null | wc -l | tr -d ' ')
  echo -e "  Scanning ${pkg_count} packages..."

  # Run pip-audit
  local audit_args=("--format" "json")
  local audit_stderr
  audit_stderr=$(mktemp "${TMPDIR:-/tmp}/pyenv-audit-err.XXXXXX")
  local raw_json
  raw_json=$("$PIP_AUDIT_BIN" --path "$site_packages" "${audit_args[@]}" 2>"$audit_stderr") || true

  if [ -z "$raw_json" ]; then
    echo -e "  ${RED}pip-audit returned no output.${RESET}"
    if [ -s "$audit_stderr" ]; then
      echo -e "  ${RED}stderr:${RESET}"
      head -10 "$audit_stderr" | sed 's/^/    /'
    fi
    rm -f "$audit_stderr"
    return 1
  fi

  if [ -s "$audit_stderr" ]; then
    local warn_count
    warn_count=$(grep -c "WARNING" "$audit_stderr" 2>/dev/null || true)
    warn_count=${warn_count:-0}
    warn_count=$(echo "$warn_count" | tr -d '[:space:]')
    if [ "$warn_count" -gt 0 ] 2>/dev/null; then
      echo -e "  ${YELLOW}${warn_count} warning(s) from pip-audit${RESET}"
    fi
  fi
  rm -f "$audit_stderr"

  # Count total vulns
  local total_vuln_count
  total_vuln_count=$(echo "$raw_json" | jq '[.dependencies[].vulns[]] | length')

  if [ "$total_vuln_count" -eq 0 ]; then
    local dep_count
    dep_count=$(echo "$raw_json" | jq '.dependencies | length')
    echo -e "  ${GREEN}No vulnerabilities found (${dep_count} packages scanned).${RESET}"
    return 0
  fi

  echo -e "  ${total_vuln_count} total vulnerability(ies) found. Enriching from OSV...\n"

  # ---- Phase 1: Collect and enrich all vulns, grouped by package ---------------
  local enriched_file
  enriched_file=$(mktemp "${TMPDIR:-/tmp}/pyenv-audit-enriched.XXXXXX")

  # Extract vulnerable packages as a JSON array, then process each
  local vuln_pkgs
  vuln_pkgs=$(echo "$raw_json" | jq -c '[.dependencies[] | select(.vulns | length > 0)]')
  local pkg_idx=0
  local pkg_total
  pkg_total=$(echo "$vuln_pkgs" | jq 'length')

  while [ "$pkg_idx" -lt "$pkg_total" ]; do
    local pkg pkg_name pkg_version
    pkg=$(echo "$vuln_pkgs" | jq -c ".[$pkg_idx]")
    pkg_name=$(echo "$pkg" | jq -r '.name')
    pkg_version=$(echo "$pkg" | jq -r '.version')

    local vuln_idx=0
    local vuln_total
    vuln_total=$(echo "$pkg" | jq '.vulns | length')

    while [ "$vuln_idx" -lt "$vuln_total" ]; do
      local vuln vuln_id aliases_json fix_versions
      vuln=$(echo "$pkg" | jq -c ".vulns[$vuln_idx]")
      vuln_id=$(echo "$vuln" | jq -r '.id')
      aliases_json=$(echo "$vuln" | jq -r '.aliases // [] | join(" ")')
      fix_versions=$(echo "$vuln" | jq -r '.fix_versions | if length > 0 then join(", ") else "" end')

      echo -e "  ${DIM}  [$((pkg_idx+1))/$pkg_total] $pkg_name: $vuln_id...${RESET}" >&2

      # Enrich from OSV
      local osv_data severity_label score_num cvss_info
      osv_data=$(enrich_vuln "$vuln_id" "$aliases_json")
      severity_label=""
      score_num="N/A"
      cvss_info=""

      if [ -n "$osv_data" ] && [ "$osv_data" != "{}" ]; then
        severity_label=$(echo "$osv_data" | jq -r '.database_specific.severity // empty')

        # Compute numeric score from CVSS vectors
        local v3_vector v4_vector
        v3_vector=$(echo "$osv_data" | jq -r '[.severity[]? | select(.type == "CVSS_V3") | .score] | first // empty')
        v4_vector=$(echo "$osv_data" | jq -r '[.severity[]? | select(.type == "CVSS_V4") | .score] | first // empty')

        if [ -n "$v3_vector" ]; then
          score_num=$(cvss3_base_score "$v3_vector")
          cvss_info="$v3_vector"
        fi
        if [ -n "$v4_vector" ]; then
          local v4_score
          v4_score=$(cvss4_base_score "$v4_vector")
          if [ "$score_num" = "N/A" ]; then
            score_num="$v4_score"
          fi
          cvss_info="${cvss_info:+${cvss_info}|}${v4_vector}"
        fi

        # Derive severity from score if DB doesn't provide one
        if [ -z "$severity_label" ] && [ "$score_num" != "N/A" ]; then
          severity_label=$(score_to_severity "$score_num")
        fi
      fi

      : "${severity_label:=UNKNOWN}"

      # Build enriched JSON safely: use jq to merge original vuln data with enrichment
      # This avoids bash variable escaping issues with descriptions containing quotes/newlines
      echo "$vuln" | jq -c \
        --arg pkg "$pkg_name" \
        --arg ver "$pkg_version" \
        --arg fix "$fix_versions" \
        --arg severity "$severity_label" \
        --arg score "$score_num" \
        --arg cvss "$cvss_info" \
        '{pkg: $pkg, ver: $ver, vid: .id,
          aliases: ((.aliases // []) | join(" ")),
          fix: $fix,
          desc: (.description // "No description available"),
          summary: (.summary // ""),
          severity: $severity,
          score: $score,
          cwes: "",
          cvss: $cvss}' >> "$enriched_file"

      # Patch in OSV summary and CWEs if available (keeps desc safe from bash)
      if [ -n "$osv_data" ] && [ "$osv_data" != "{}" ]; then
        local osv_summary osv_cwes
        osv_summary=$(echo "$osv_data" | jq -r '.summary // empty')
        osv_cwes=$(echo "$osv_data" | jq -r '.database_specific.cwe_ids // [] | join(", ")')
        if [ -n "$osv_summary" ] || [ -n "$osv_cwes" ]; then
          # Update last line of enriched file
          local tmp_patch last_line total_lines
          tmp_patch=$(mktemp "${TMPDIR:-/tmp}/pyenv-audit-patch.XXXXXX")
          last_line=$(tail -1 "$enriched_file")
          total_lines=$(wc -l < "$enriched_file" | tr -d '[:space:]')
          if [ "$total_lines" -gt 1 ]; then
            sed '$d' "$enriched_file" > "$tmp_patch"
          else
            : > "$tmp_patch"
          fi
          echo "$last_line" | jq -c \
            --arg summary "$osv_summary" \
            --arg cwes "$osv_cwes" \
            '.summary = (if $summary != "" then $summary else .summary end) |
             .cwes = (if $cwes != "" then $cwes else .cwes end)' >> "$tmp_patch"
          mv "$tmp_patch" "$enriched_file"
        fi
      fi

      vuln_idx=$((vuln_idx + 1))
    done
    pkg_idx=$((pkg_idx + 1))
  done

  # ---- Phase 2: Filter by severity threshold -----------------------------------
  local min_level
  min_level=$(threshold_num)

  local filtered_file
  filtered_file=$(mktemp "${TMPDIR:-/tmp}/pyenv-audit-filtered.XXXXXX")

  while IFS= read -r line; do
    [ -z "$line" ] && continue
    local sev sev_num
    sev=$(echo "$line" | jq -r '.severity')
    sev_num=$(severity_to_num "$sev")
    if [ "$sev_num" -ge "$min_level" ]; then
      echo "$line" >> "$filtered_file"
    fi
  done < "$enriched_file"

  local filtered_count total_enriched_count
  total_enriched_count=$(grep -c '' "$enriched_file" 2>/dev/null || echo 0)
  filtered_count=$(grep -c '' "$filtered_file" 2>/dev/null || echo 0)

  if [ "$filtered_count" -eq 0 ]; then
    echo -e "  ${GREEN}No vulnerabilities at severity >= ${SEVERITY_THRESHOLD} (${total_enriched_count} total found, filtered out).${RESET}"
    rm -f "$enriched_file" "$filtered_file"
    return 0
  fi

  if [ "$SEVERITY_THRESHOLD" != "ALL" ]; then
    echo -e "  Showing ${filtered_count}/${total_enriched_count} vulnerabilities (severity >= ${SEVERITY_THRESHOLD})\n"
  fi

  # ---- Phase 3: Display grouped by package -------------------------------------
  local fix_commands=""

  # Get sorted unique package names
  local packages
  packages=$(jq -r '.pkg' "$filtered_file" | sort -u)

  while IFS= read -r current_pkg; do
    [ -z "$current_pkg" ] && continue

    # Get package version and count
    local pkg_ver pkg_vuln_count
    pkg_ver=$(jq -r "select(.pkg == \"$current_pkg\") | .ver" "$filtered_file" | head -1)
    pkg_vuln_count=$(jq -r "select(.pkg == \"$current_pkg\") | .vid" "$filtered_file" | wc -l | tr -d ' ')

    # Get highest fix version for this package
    local best_fix
    best_fix=$(jq -r "select(.pkg == \"$current_pkg\") | .fix" "$filtered_file" | grep -v '^$' | sort -V | tail -1 2>/dev/null || true)

    echo -e "  ${BOLD}--- ${current_pkg}==${pkg_ver} (${pkg_vuln_count} issue(s)) ---${RESET}"
    if [ -n "$best_fix" ]; then
      echo -e "  ${GREEN}Upgrade to: ${best_fix}${RESET}"
      fix_commands="${fix_commands}${current_pkg}>=${best_fix} "
    else
      echo -e "  ${YELLOW}No fix version available${RESET}"
    fi
    echo ""

    # List each vuln for this package
    jq -c "select(.pkg == \"$current_pkg\")" "$filtered_file" | while IFS= read -r record; do
      local vid sev score summary desc cvss cwes aliases fix_ver
      vid=$(echo "$record" | jq -r '.vid')
      sev=$(echo "$record" | jq -r '.severity')
      score=$(echo "$record" | jq -r '.score')
      summary=$(echo "$record" | jq -r '.summary')
      desc=$(echo "$record" | jq -r '.desc')
      cvss=$(echo "$record" | jq -r '.cvss')
      cwes=$(echo "$record" | jq -r '.cwes')
      aliases=$(echo "$record" | jq -r '.aliases')
      fix_ver=$(echo "$record" | jq -r '.fix')

      # Severity with color
      echo -ne "    "
      severity_color "$sev"
      if [ "$score" != "N/A" ] && [ -n "$score" ]; then
        echo -e "${sev} (${score}/10)${RESET}  ${BOLD}${vid}${RESET}"
      else
        echo -e "${sev}${RESET}  ${BOLD}${vid}${RESET}"
      fi

      if [ -n "$aliases" ] && [ "$aliases" != "" ]; then
        echo -e "    ${DIM}Aliases: ${aliases}${RESET}"
      fi

      if [ -n "$summary" ] && [ "$summary" != "" ]; then
        echo -e "    ${summary}"
      elif [ -n "$desc" ]; then
        # Truncate description
        if [ ${#desc} -gt 120 ]; then
          echo -e "    ${desc:0:120}..."
        else
          echo -e "    ${desc}"
        fi
      fi

      if [ -n "$cwes" ] && [ "$cwes" != "" ]; then
        echo -e "    ${DIM}CWE: ${cwes}${RESET}"
      fi

      if [ -n "$fix_ver" ] && [ "$fix_ver" != "" ]; then
        echo -e "    ${DIM}Fix: ${fix_ver}${RESET}"
      fi

      echo ""
    done
  done <<< "$packages"

  # ---- Phase 4: Fix mode -------------------------------------------------------
  if [ -n "$fix_commands" ] && { [ "$MODE" = "fix" ] || [ "$MODE" = "dry-run" ]; }; then
    echo -e "  ${BOLD}${CYAN}--- Upgrade plan ---${RESET}"
    local pip_target="${pip_bin%pip}pip"
    local upgrade_cmd="$pip_target install --upgrade $fix_commands"

    echo -e "  ${upgrade_cmd}\n"

    if [ "$MODE" = "fix" ]; then
      echo -e "  ${YELLOW}Executing upgrades...${RESET}\n"
      eval "$upgrade_cmd" 2>&1 | sed 's/^/    /'
      local exit_code=$?
      if [ $exit_code -eq 0 ]; then
        echo -e "\n  ${GREEN}Upgrades applied successfully.${RESET}"
        echo -e "  ${CYAN}Re-run pyenv-audit.sh to verify.${RESET}"
      else
        echo -e "\n  ${RED}Some upgrades failed (exit code $exit_code).${RESET}"
        echo -e "  ${YELLOW}Review the output above and fix manually if needed.${RESET}"
      fi
    else
      echo -e "  ${YELLOW}Dry run — no changes made. Run with --fix to apply.${RESET}"
    fi
  fi

  rm -f "$enriched_file" "$filtered_file"
}

# --- Main -----------------------------------------------------------------------
echo -e "${BOLD}pyenv-audit — Auditing all Python versions${RESET}"
echo -e "Mode: ${BOLD}$MODE${RESET}  |  Severity: ${BOLD}>= $SEVERITY_THRESHOLD${RESET}"
echo -e "pip-audit: $PIP_AUDIT_BIN"
echo -e "cvss: ${CVSS_PYTHON:-not available (scores will show N/A)}"
echo -e "pyenv root: $PYENV_ROOT"

found=0
for pip_bin in "$PYENV_ROOT"/versions/*/bin/pip; do
  [ -x "$pip_bin" ] || continue

  if [ -n "$FILTER_VERSION" ]; then
    ver_name=$(basename "$(dirname "$(dirname "$pip_bin")")")
    if [ "$ver_name" != "$FILTER_VERSION" ]; then
      continue
    fi
  fi

  found=$((found + 1))
  audit_version "$pip_bin"
done

if [ "$found" -eq 0 ]; then
  if [ -n "$FILTER_VERSION" ]; then
    echo -e "${YELLOW}Version $FILTER_VERSION not found in $PYENV_ROOT/versions/${RESET}"
  else
    echo -e "${YELLOW}No pyenv versions found in $PYENV_ROOT/versions/*/bin/pip${RESET}"
  fi
  exit 1
fi

echo -e "\n${BOLD}Audit complete. $found version(s) scanned.${RESET}"
