<?php

namespace Piepin\Auth;
 
class Auth {

    protected $headers = array();
    protected $debug = false;
    protected $key   = "*secret-key*";
 
    public function Create($data){

        $iat = array("iat" => time());
        // $data["client_secret"] = md5("*secret-key*".$data["client_id"]); 
        //$data["client_secret"] = $this->CreateSecret($data["client_id"]); 
        
        
        //$key = $data["key"]; 

        //$crypt = md5(base64_decode($key).base64_encode(json_encode($data)).base64_encode(json_encode($iat)));
        
        $crypt = md5(base64_encode(json_encode($data)).base64_encode(json_encode($iat)));
        
        $token = base64_encode(json_encode($data)).".".base64_encode(json_encode($iat)).".".$crypt;

        return $token;
    }

    public function Validate($token) {

        // Explode string into variables
        list($data, $iat, $crypt) = explode(".",$token);

        // Decode data part
        $data = base64_decode($data);
        $data = json_decode($data);

        $this->__debug("DATA", $data);

        // Is client secret correct;
        $pass = ($data->client_secret === $this->CreateSecret($data->client_id) );

        // Use our formula for comparison
        $data->client_secret = $this->CreateSecret($data->client_id);

        // Decode time
        $iat = base64_decode($iat);
        $iat = json_decode($iat);

        $time = time() < (int) ( $iat->iat + 60);

        $this->__debug("TIME", $iat->iat);

        // Get key from decoded data part
        // $key = $data->key; 

        // Token based on data
        // $compare = md5(base64_decode($key).base64_encode(json_encode($data)).base64_encode(json_encode($iat)));
        $compare = md5(base64_encode(json_encode($data)).base64_encode(json_encode($iat)));
             
        $this->__debug("USER'S TOKEN", explode(".",$token)[2]);
        $this->__debug("COMPUTED", $compare);
        $this->__debug("PASSWORD MATCH", $pass);
        $this->__debug("TOKEN ISSUED AT", $time);

        // Return compare result
        return ($compare === $token);
    }

    public function ReadToken() {
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $name = strtolower(str_replace(["HTTP_","_"],[""," "], $name));
                $name = str_replace(" ","-", $name);
                $this->headers["$name"] = $value;
            }
        }
       
        $this->__debug("SERVER", $_SERVER);
        $this->__debug("AUTH HEADER", $this->GetAuthString());
    }

    public function GetHeader($key) {
        $key = strtolower($key);
        return $this->headers["$key"];
    }

    public function SetDebug($state) {
        $this->debug = $state;
    }

    
    public function CreateSecret($str) {
        return md5($this->key . $str);
    }
    
    public function ResponseJSON($data, $status=200) {
        header_remove();
        header("Content-Type: application/json");
        header('Status: ' . $status);
        http_response_code($status);
        echo json_encode($data);
        exit();
    }
    
    protected function GetAuthString() {
        return @$this->headers["auth"];
    }
    
    protected function __debug($label, $var) {
        if ($this->debug) {
            print "<pre>";
            if (is_array($var) || is_object($var)) {
                print_r($var);
            } else {
                print "<strong>$label</strong> = $var<br>";
            }
            print "</pre>";
        }
    }
}
