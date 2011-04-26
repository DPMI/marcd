#!/bin/bash


index=0;
while [ true ] 
do
  echo "MArC start for the $index time. "
   ./MArCd -h localhost -d marc -u marc -p konko
  index=`expr $index + 1`
done