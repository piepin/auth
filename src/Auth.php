<?php

namespace Piepin\Auth;
 
class Auth {

    protected $headers      = array();
    protected $debug        = false;
    protected $key          = "*secret-key*";
    protected $db           = null;
    protected $user_col     = "username";
    protected $pass_col     = "password";
    protected $user_table   = "users";

    public function SetDatabase($pdo) {
        $this->db = $pdo;
    }
 
    public function Create($data){

        // Now
        $iat = array("iat" => time());

        // Encrypt real password
        $data["client_secret"] = $this->CreateSecret($data["client_id"]); 
        
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
        $this->__debug("DATA", $data);
        $data = base64_decode($data);
        $data = json_decode($data);

        $this->__debug("DATA DECODED", $data);

        //=== Is client secret correct?
        if ( $data->client_secret !== $this->CreateSecret($data->client_id) ) {
            //return false;
        }

        // Use our formula for comparison
        $data->client_secret = $this->CreateSecret($data->client_id);

        // Decode time
        $iat = base64_decode($iat);
        $iat = json_decode($iat);
        $this->__debug("TIME", $iat->iat);
        
        //=== Is time expired?
        if ( time() >= (int) ( $iat->iat + 60) ) {
            //return false;
        }

        //=== Compare token
        $compare = md5(base64_encode(json_encode($data)).base64_encode(json_encode($iat)));
        $this->__debug("USER'S TOKEN", explode(".",$token)[2]);
        $this->__debug("COMPUTED    ", $compare);
        // $this->__debug("PASSWORD MATCH", $pass);
        // $this->__debug("TOKEN ISSUED AT", $time);
        if ($compare !== $token) {
            //return false;
        }

        //=== Check user and password in PDO database
        try {
            if ($this->db != null) {
                $sql = "SELECT COUNT(*) AS num FROM user WHERE username = :user and password = :pass";
                $stmt = $this->db->prepare($sql);
                $stmt->bindValue(':user', $data->client_id, \PDO::PARAM_STR);
                $stmt->bindValue(':pass', $data->client_secret, \PDO::PARAM_STR);
                $stmt->execute();
                $row = $stmt->fetch(\PDO::FETCH_ASSOC);
                if($row['num'] <= 0) {
                    //return false;
                } 
            } else {
                throw new \Exception("The database has not been set.");
            }
        } catch (Exception $e) {
            echo $e->getMessage();
            die();
        }

        //=== Every validation steps is passed, return true
        return true;
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

    public function SetUserTable($table, $user, $pass) {
        $this->user_table = $table;
        $this->user_col   = $user;
        $this->pass_col   = $pass;
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
