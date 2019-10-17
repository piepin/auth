<?php
/**
 * Simple Authorization class with PHP
 *
 * 1. CLIENT --->[send user + pass]---> SERVER
 *    Client post user + password to server  
 * 
 * 2. CLIENT <---[token           ]<--- SERVER
 *    If password or token is correct, 
 *    server will create token and send response to client
 *  
 * 3. CLIENT --->[token + request ]---> SERVER
 *    Client post request data + token to server
 * 
 * 4. CLIENT <---[response        ]<--- SERVER
 *    If token and password is correct and not expired,
 *    server will send asked data in JSON format 
 *
 * @version    Release: @package_version@
 * @author     Piepin <piepin7228@gmail.com>
 * @license    https://opensource.org/licenses/MIT MIT License
 * @link       https://github.com/piepin/auth
 * @since      File available since Release 1.0.0
 */ 

namespace Piepin\Auth;
 
class Auth {

    /**
     * Encryption key, please change
     * @var string $headers
     */
    protected $key          = "*~/secret^&^key/~*";
    
    /**
     * Holds the header from the client
     * @var string $headers
     */
    protected $headers      = array();

    /**
     * Dump variables when debug is set to true
     * @var bool $debug
     */
    protected $debug        = false;
    
    /**
     * Holds database object
     * @var object $db
     */
    protected $db;

    /**
     * Holds table's name and field's name
     * @var string $user_table
     * @var string $user_col
     * @var string $pass_col
     */
    protected $user_col     = "username";
    protected $pass_col     = "password";
    protected $user_table   = "users";

    /**
     * Set database object (PDO)
     *
     * Set database object (PDO) for user and password validation.
     *
     * @param object $pdo PDO database object
     * @return bool  Return true is parameter is object
     *
     * @access public
     */
    public function SetDatabase($pdo) {
        $this->db = $pdo;
        return (is_object($pdo));
    }

    /**
     * Create security token 
     *
     * Create simple token based on my own algorithm :)  
     *  
     * Parameter format: 
     * $data = array( "client_id" => "myusername",
     *                "client_secret" => $auth->CreateSecret("mypassword") );
     *
     * @param array   $data Login data 
     * @return string Token created
     *
     * @access public
     */
     public function CreateToken($data){

        // Issued at now
        $iat = array("iat" => time());

        // Encrypt real password
        $data["client_secret"] = $this->CreateSecret($data["client_id"]); 

        // Create token
        $crypt = md5(base64_encode(json_encode($data)).base64_encode(json_encode($iat)));
        $token = base64_encode(json_encode($data)).".".base64_encode(json_encode($iat)).".".$crypt;

        return $token;
    }

    public function ValidateToken($token) {

        // Explode string into variables
        @list($data, $iat, $crypt) = explode(".",$token);

        // Decode data part
        $this->__debug("DATA", $data);
        $data = base64_decode($data);
        $data = json_decode($data);
        $this->__debug("DATA DECODED", $data);

        //=== Is client secret correct?
        if ( $data->client_secret !== $this->CreateSecret($data->client_id) ) {
            if (!$this->debug) {
                return false;
            }
        }

        // Use our formula for comparison
        $data->client_secret = $this->CreateSecret($data->client_id);

        // Decode time
        $iat = base64_decode($iat);
        $iat = json_decode($iat);
        $this->__debug("TIME", $iat->iat);
        
        //=== Is time expired?
        if ( time() >= (int) ( $iat->iat + 31536000 ) ) {
            if (!$this->debug) {
                return false;
            }
        }

        //=== Compare token
        $compare = md5(base64_encode(json_encode($data)).base64_encode(json_encode($iat)));
        $this->__debug("USER'S TOKEN", explode(".",$token)[2]);
        $this->__debug("COMPUTED    ", $compare);
        // $this->__debug("PASSWORD MATCH", $pass);
        // $this->__debug("TOKEN ISSUED AT", $time);
        if ($compare !== $token) {
            if (!$this->debug) {
                return false;
            }
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
                    if (!$this->debug) {
                        return false;
                    }
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
        
        // preg_match('/Bearer\s(\S+)/i', $this->GetAuthString(), $out);
        // return $out[1];

        return $this->GetAuthString();
    }

    public function ReadPost() {
        $raw = file_get_contents('php://input');
        parse_str($raw, $post);
        return $post;
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
        if (!headers_sent()) {
            header_remove();
            //header('Status: ' . $status);
            http_response_code($status);
            header("Server: West Java");
            header("Content-Type: application/json");
            http_response_code($status);
            echo json_encode($data);
            die();
        } else {
            $this->__debug("ERROR", "Header already sent.");
            $this->__debug("HEADER", headers_list());
            die();
        }
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

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * End:
 */
