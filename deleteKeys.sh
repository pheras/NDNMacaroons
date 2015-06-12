#!/bin/bash

PRODUCER_ID=/ndn/keys/producer
CONSUMER1_ID=/ndn/keys/consumer1
CONSUMER2_ID=/ndn/keys/consumer2
THIRD_PARTY_ID=/ndn/keys/thirdParty

ID_LIST="$PRODUCER_ID $CONSUMER1_ID $CONSUMER2_ID $THIRD_PARTY_ID"

for id in $ID_LIST
do
   ndnsec-delete $id 
done

rm ./keys.txt ./config/*.cert

