#!/bin/bash
set -e

echo "Creating user..."
CREATE_RESPONSE=$(curl -s -X POST http://localhost:8080/api/user/create \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Secure123!","first_name":"John","surname":"Doe"}')
echo $CREATE_RESPONSE

echo -e "\nLogging in..."
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8080/api/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Secure123!"}' \
  -c cookies.txt)
echo $LOGIN_RESPONSE

echo -e "\nChecking profile..."
PROFILE_RESPONSE=$(curl -s -X GET http://localhost:8080/api/user/profile \
  -b cookies.txt)
echo $PROFILE_RESPONSE

echo -e "\nLogging out..."
LOGOUT_RESPONSE=$(curl -s -X POST http://localhost:8080/api/user/logout \
  -b cookies.txt \
  -c cookies.txt)
echo $LOGOUT_RESPONSE

echo -e "\nTrying profile after logout (should fail)..."
FAILED_PROFILE_RESPONSE=$(curl -s -X GET http://localhost:8080/api/user/profile \
  -b cookies.txt)
echo $FAILED_PROFILE_RESPONSE
