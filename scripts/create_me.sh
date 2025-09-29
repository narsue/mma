#!/bin/bash
set -e

echo "Creating user..."
CREATE_RESPONSE=$(curl -s -X POST http://localhost:1227/api/user/create \
  -H "Content-Type: application/json" \
  -d '{"email":"sam@test.com","password":"test","first_name":"John","surname":"Doe"}')
echo $CREATE_RESPONSE

echo "Creating user..."
CREATE_RESPONSE=$(curl -s -X POST http://localhost:1227/api/user/create \
  -H "Content-Type: application/json" \
  -d '{"email":"narsue@school1.com","password":"Secure123!","first_name":"John","surname":"Doe"}')
echo $CREATE_RESPONSE

# curl -s -X POST http://localhost:1228/api/user/create -H "Content-Type: application/json" -d '{"email":"sam@test.com","password":"test","first_name":"John","surname":"Doe"}'

# "email":"narsue@school1.com","password":"Secure123!"