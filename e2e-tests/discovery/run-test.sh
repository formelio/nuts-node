#!/usr/bin/env bash
source ../../util.sh

echo "------------------------------------"
echo "Cleaning up running Docker containers and volumes, and key material..."
echo "------------------------------------"
docker compose down
docker compose rm -f -v
rm -rf ./client/data
rm -rf ./server/data
mkdir ./server/data ./client/data  # 'data' dirs will be created with root owner by docker if they do not exit. This creates permission issues on CI.

echo "------------------------------------"
echo "Starting Docker containers..."
echo "------------------------------------"
docker compose up -d
docker compose up --wait server client

echo "------------------------------------"
echo "Registering vendors..."
echo "------------------------------------"
# Register DID
DIDDOC=$(docker compose exec nodeA-backend nuts vdr create-did --v2)
DID=$(echo $DIDDOC | jq -r .id)
echo Cliuent DID: $DID

# Issue NutsOrganizationCredential and load it into client wallet
REQUEST="{\"type\":\"NutsOrganizationCredential\",\"issuer\":\"${DID}\", \"credentialSubject\": {\"id\":\"${DID}\", \"organization\":{\"name\":\"Caresoft B.V.\", \"city\":\"Caretown\"}},\"publishToNetwork\": false}"
VC_RESPONSE=$(echo $REQUEST | docker compose exec client curl -X POST --data-binary @- http://localhost:1323/internal/vcr/v2/issuer/vc -H "Content-Type:application/json")
if echo $RESPONSE | grep -q "VerifiableCredential"; then
  echo "VC issued"
else
  echo "FAILED: Could not issue NutsOrganizationCredential" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

RESPONSE=$(echo $VC_RESPONSE | docker compose exec client curl -X POST --data-binary @- http://localhost:1323/internal/vcr/v2/holder/${DID}/vc -H "Content-Type:application/json")
if echo $RESPONSE == ""; then
  echo "VC stored in wallet"
else
  echo "FAILED: Could not load NutsOrganizationCredential in client wallet" 1>&2
  echo $RESPONSE
  exitWithDockerLogs 1
fi

echo "---------------------------------------"
echo "Register VP on Discovery Service..."
echo "---------------------------------------"


echo "------------------------------------"
echo "Stopping Docker containers..."
echo "------------------------------------"
docker compose stop
