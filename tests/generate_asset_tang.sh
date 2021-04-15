mkdir assets/tang
/usr/lib/tangd-keygen assets/tang sig exc
/usr/lib/tangd assets/tang <<<$'GET /adv HTTP/1.1\n\n' | grep payload >assets/tang/adv.jwk
