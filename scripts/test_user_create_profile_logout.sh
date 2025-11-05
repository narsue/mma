#!/bin/bash
set -e

echo "Creating user..."
CREATE_RESPONSE=$(curl -s -X POST http://localhost:1227/api/user/create \
  -H "Content-Type: application/json" \
  -d '{"email":"narsue@example.com","password":"test","first_name":"John","surname":"Doe"}')
echo $CREATE_RESPONSE

echo -e "\nLogging in..."
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:1227/api/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"narsue@example.com","password":"test"}' \
  -c cookies.txt)
echo $LOGIN_RESPONSE

cat cookies.txt

echo -e "\nChecking profile..."
PROFILE_RESPONSE=$(curl -s -X GET http://localhost:1227/api/user/profile \
  -b cookies.txt)
echo $PROFILE_RESPONSE

echo -e "\n Getting class list"
PROFILE_RESPONSE=$(curl -s -X GET http://localhost:1227/api/class/get_list \
  -H "Content-Type: application/json" \
  -b cookies.txt)
echo $PROFILE_RESPONSE




echo -e "\n Getting students in class..."
PROFILE_RESPONSE=$(curl -s -X POST http://localhost:1227/api/class/get_students \
  -d '{"class_id":"74514650-06c9-4cf1-bc9d-191748ff9313","class_start_ts":0}' \
  -H "Content-Type: application/json" \
  -b cookies.txt)
echo $PROFILE_RESPONSE


echo -e "\n Create a style ..."
STYLE_RESPONSE=$(curl -s -X POST http://localhost:1227/api/style/create \
  -d '{"title":"style3","description":"style3"}' \
  -H "Content-Type: application/json" \
  -b cookies.txt)
echo $STYLE_RESPONSE

# extract `.id` into STYLE_ID
STYLE_ID=$(echo "$STYLE_RESPONSE" | jq -r .id)
echo "Created style with ID: $STYLE_ID"

# Venue creation
echo -e "\nCreate a venue ..."
VENUE_RESPONSE=$(curl -s -X POST http://localhost:1227/api/venue/create \
  -d '{"title":"Venue1","description":"Venue1","address":"asd","suburb":"asd","state":"asd","postcode":"asd","country":"asd","latitude":123,"longitude":123,"contact_phone":"123"}' \
  -H "Content-Type: application/json" \
  -b cookies.txt)
echo $VENUE_RESPONSE

VENUE_ID=$(echo "$VENUE_RESPONSE" | jq -r .id)
echo "Created venue with ID: $VENUE_ID"

# Class creation
echo -e "\nCreate a class ..."
CLASS_RESPONSE=$(curl -s -X POST http://localhost:1227/api/class/create \
  -d "{\"title\":\"class1\",
      \"description\":\"class1\",
      \"venue_id\":\"$VENUE_ID\",
      \"style_ids\":[\"$STYLE_ID\"],
      \"grading_ids\":[],
      \"price\":null,
      \"publish_mode\":0,
      \"capacity\":10,
      \"frequency\":[
        {\"frequency\":1,
        \"start_date\":\"2025-07-01\",
        \"end_date\":\"2046-07-01\",
        \"start_time\":\"01:00:00\",
        \"end_time\":\"10:02:00\"}
      ],
      \"notify_booking\":false,
      \"waiver_id\":null}" \
  -H "Content-Type: application/json" \
  -b cookies.txt)
echo $CLASS_RESPONSE

CLASS_ID=$(echo "$CLASS_RESPONSE" | jq -r .id)
echo "Created class with ID: $CLASS_ID"

# Create a student account for this school
echo "Creating student user..."
CREATE_RESPONSE=$(curl -s -X POST http://localhost:1227/api/user/update_profile \
  -H "Content-Type: application/json" \
  -d '{"user_id":"00000000-0000-0000-0000-000000000001","first_name":"Jason","surname":"Traish","gender":"male","phone":"","dob":"2025/11/13","address":"","suburb":"","emergency_name":"","emergency_relationship":"","emergency_phone":"","emergency_medical":"","belt_size":"","uniform_size":"","email":"narsue@hotmail.com"}' \
  -b cookies.txt)
echo $CREATE_RESPONSE


echo -e "\nLogging out..."
LOGOUT_RESPONSE=$(curl -s -X POST http://localhost:1227/api/user/logout \
  -b cookies.txt \
  -c cookies.txt)
echo $LOGOUT_RESPONSE


echo -e "\nTrying profile after logout (should fail)..."
FAILED_PROFILE_RESPONSE=$(curl -s -X GET http://localhost:1227/api/user/profile \
  -b cookies.txt)
echo $FAILED_PROFILE_RESPONSE
