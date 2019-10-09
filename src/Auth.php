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

        list($data, $iat, $crypt) = explode(".",$token);

        $data = base64_decode($data);
        $data = json_decode($data);
        print_r($data);

        $pass = ($data->client_secret === md5("rahasia".$data->client_id));

        $iat = base64_decode($iat);
        $iat = json_decode($iat);
        print_r($iat);

        $key = $data->key; 

        $compare = md5(base64_decode($key).base64_encode(json_encode($data)).base64_encode(json_encode($iat)));

        return ($compare === $token);

        /*      
        print "COMPARE = $compare<br>";
        print "TOKEN   = $crypt<br>";
        print "PASS    = $pass<br>";
        */        
    }

}
