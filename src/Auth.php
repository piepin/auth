<?php

namespace Piepin\Auth;
 
class Auth {

    private $headers = array();
 
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

        $time = time() < (int) ( $iat->iat + 60);

        print_r($iat->iat);

        // Get key from decoded data part
        $key = $data->key; 

        // Token based on data
        $compare = md5(base64_decode($key).base64_encode(json_encode($data)).base64_encode(json_encode($iat)));
             
        print "<br>";
        print "COMPARE = $compare<br>";
        print "TOKEN   = ". explode(".",$token)[2] . "<br>";
        print "PASS    = $pass<br>";
        print "TIME    = $time<br>";

        /*
        print "TOKEN   = $crypt<br>";
        print "PASS    = $pass<br>";
        */      

        // Return compare result
        return ($compare === $token);
    }

    public function Read() {
        print_r($_SERVER);

        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $name = ucwords(strtolower(str_replace(["HTTP_","_"],[""," "], $name)));
                $this->headers["$name"] = $value;
            }
        }
        print_r($this->headers);
        print $this->GetAuthString();
    }

    private function GetAuthString() {
        return $this->headers["Auth"];
    }

}
