<?php

namespace Piepin\Auth;
 
class Auth {
 
    public function Create($data){

        $iat = array("iat" => time());
        $key = $data["key"]; 

        $crypt = md5(base64_decode($key).base64_encode(json_encode($data)).base64_encode(json_encode($iat)));
        $token = base64_encode(json_encode($data)).".".base64_encode(json_encode($iat)).".".$crypt;

        return $token;
    }

    public function Validate($token) {

        // Explode string into variables
        list($data, $iat, $crypt) = explode(".",$token);

        // Decode data part
        $data = base64_decode($data);
        $data = json_decode($data);
        print_r($data);

        // Is client secret correct;
        $pass = ($data->client_secret === md5("rahasia".$data->client_id));

        // Decode time
        $iat = base64_decode($iat);
        $iat = json_decode($iat);
        print_r($iat);

        print_r($iat->iat);

        // Get key from decoded data part
        $key = $data->key; 

        // Token based on data
        $compare = md5(base64_decode($key).base64_encode(json_encode($data)).base64_encode(json_encode($iat)));
             
        print "COMPARE = $compare<br>";
        print "TOKEN   = $token<br>";

        /*
        print "TOKEN   = $crypt<br>";
        print "PASS    = $pass<br>";
        */      

        // Retun compare result
        return ($compare === $token);
    }
}
