#!/bin/bash

echo "Running benchmarks"

# Fetch version from API endpoint
APP_VERSION=$(curl -s http://127.0.0.1:1227/api/version | tr -d '\r\n"')

if [[ -z "$APP_VERSION" ]]; then
  echo "Failed to get app version from /api/version"
  exit 1
fi

echo "App version: $APP_VERSION"
CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')

# Authenticate and get cookie
COOKIE=$(curl -s -i -X POST http://127.0.0.1:1227/api/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"narsue@school1.com","password":"Secure123!"}' \
  | awk '/^[Ss]et-[Cc]ookie:/ { 
      split($0, a, ": "); 
      split(a[2], b, ";"); 
      cookies = cookies b[1] "; " 
    } 
    END { 
      sub(/; $/, "", cookies); 
      print cookies 
    }')

# echo "Using cookie: $COOKIE"

# Create benchmark output dir
SUMMARY_FILE="benchmark_results/$APP_VERSION/summary.txt"
mkdir -p "$(dirname "$SUMMARY_FILE")"
# echo -n "" > "$SUMMARY_FILE"  # Clear previous summary
echo "CPU: $CPU_MODEL" | tee -a "$SUMMARY_FILE"
echo "" | tee -a "$SUMMARY_FILE"

# Optional header
printf "%-25s | %-20s | %-20s | %-20s | %-20s\n" \
  "Benchmark" "Req/sec" "Avg latency" "90%" "99%" | tee -a "$SUMMARY_FILE"
printf -- "-----------------------------------------------------------------------------------------------\n" | tee -a "$SUMMARY_FILE"

run_benchmark() {
  local name="$1"
  local cmd="$2"

  local dir="benchmark_results/$APP_VERSION/$name"
  mkdir -p "$dir"

  eval "$cmd" > "$dir/result.txt"

  local req=$(grep "Requests/sec:" "$dir/result.txt" | awk '{print $2}')
  local avg=$(grep "Average:" "$dir/result.txt" | awk '{print $2}')
  local lat90=$(grep "90% in" "$dir/result.txt" | awk '{print $3}')
  local lat99=$(grep "99% in" "$dir/result.txt" | awk '{print $3}')

  # ANSI colors
  RED='\033[0;31m'
  NC='\033[0m'

  # Strip decimals for integer comparison
  local req_int=${req%.*}

  # Pad to fixed width for alignment (even with ANSI codes)
  local req_formatted
  if [ "$req_int" -lt 1000 ]; then
    req_formatted=$(printf "${RED}%-20s${NC}" "$req")
  else
    req_formatted=$(printf "%-20s" "$req")
  fi

  # Output with consistent alignment
  printf "%-25s | %s | %-20s | %-20s | %-20s\n" \
    "$name" "$req_formatted" "${avg}s" "${lat90}s" "${lat99}s" | tee -a "$SUMMARY_FILE"
}


run_benchmark version "hey -n 1000 -c 10 http://127.0.0.1:1227/api/version"
run_benchmark health "hey -n 1000 -c 10 http://127.0.0.1:1227/api/health"

run_benchmark home_page "hey -n 1000 -c 10 http://127.0.0.1:1227"

run_benchmark login_success "hey -n 500 -c 5 -m POST -H 'Content-Type: application/json' -d '{\"email\":\"narsue@school1.com\",\"password\":\"Secure123!\"}' http://127.0.0.1:1227/api/user/login"

run_benchmark login_bad_password_fail "hey -n 500 -c 5 -m POST -H 'Content-Type: application/json' -d '{\"email\":\"narsue@school1.com\",\"password\":\"test\"}' http://127.0.0.1:1227/api/user/login"

run_benchmark login_no_user_fail "hey -n 500 -c 5 -m POST -H 'Content-Type: application/json' -d '{\"email\":\"test@test.com\",\"password\":\"test\"}' http://127.0.0.1:1227/api/user/login"

run_benchmark api/class/get_list "hey -n 500 -c 5 -H 'Cookie: $COOKIE' http://127.0.0.1:1227/api/class/get_list"
run_benchmark api/style/get_list "hey -n 500 -c 5 -H 'Cookie: $COOKIE' http://127.0.0.1:1227/api/style/get_list"
run_benchmark api/venue/get_list "hey -n 500 -c 5 -H 'Cookie: $COOKIE' http://127.0.0.1:1227/api/venue/get_list"

# Fetch first class_id using authenticated request
CLASS_ID=$(curl -s -H "Cookie: $COOKIE" http://127.0.0.1:1227/api/class/get_list \
  | jq -r '.[0].class_id')

if [[ -z "$CLASS_ID" || "$CLASS_ID" == "null" ]]; then
  echo "Failed to fetch class_id"
  exit 1
fi

# echo "Using class_id: $CLASS_ID"
run_benchmark api/class/get_class "hey -n 500 -c 5 -m POST -H 'Content-Type: application/json' -H 'Cookie: $COOKIE' -d '{\"class_id\":\"$CLASS_ID\"}' http://127.0.0.1:1227/api/class/get_class"

# Fetch first class_id using authenticated request
STYLE_ID=$(curl -s -H "Cookie: $COOKIE" http://127.0.0.1:1227/api/style/get_list \
  | jq -r '.styles[0].style_id')

if [[ -z "$STYLE_ID" || "$STYLE_ID" == "null" ]]; then
  echo "Failed to fetch style_id"
  exit 1
fi

# echo "Using style_id: $STYLE_ID"
run_benchmark api/class/get_style "hey -n 500 -c 5 -m POST -H 'Content-Type: application/json' -H 'Cookie: $COOKIE' -d '{\"style_id\":\"$STYLE_ID\"}' http://127.0.0.1:1227/api/style/get_class"
