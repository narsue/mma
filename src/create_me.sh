#!/bin/bash
set -e

echo "Creating user..."
CREATE_RESPONSE=$(curl -s -X POST http://localhost:1227/api/user/create \
  -H "Content-Type: application/json" \
  -d '{"email":"narsue@hotmail.com","password":"test","first_name":"John","surname":"Doe"}')
echo $CREATE_RESPONSE