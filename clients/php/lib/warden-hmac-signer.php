<?php

# warden-hmac-signer
# a signing client for the https://github.com/Asquera/warden-hmac-authentication library
#		

class WardenHmacSigner {

	protected $algorithm;
	protected $defaultOts;

	public function __construct($algorithm = "sha1", $default_opts = array()) {
		$this->algorithm = $algorithm;
		$this->defaultOpts = array(
			"auth_scheme" => "HMAC",
		    "auth_param" => "auth",
		    "auth_header" => "Authorization",
		    "auth_header_format" => "%{auth_scheme} %{signature}",
		    "nonce_header" => "X-%{scheme}-Nonce", #% {:scheme => (default_opts[:auth_scheme] || "HMAC")},
		    "alternate_date_header" => "X-%{scheme}-Date", # % {:scheme => (default_opts[:auth_scheme] || "HMAC")},
		    "query_based" => false,
		    "use_alternate_date_header" => false,
		    "extra_auth_params" => array()
		) + $default_opts;
	}

	# returns the canonical representation for the given list of parameters
	public function canonicalRepresentation($params) {
		$rep = "";
		
		$rep .= strtoupper($params["method"]) . "\n";
		$rep .= "date:".$params["date"]."\n";
		$rep .= "nonce:".$params["nonce"]."\n";
	
		if (empty($params["headers"])) {
			$headers = array();
		} else {
			$headers = $params["headers"];
		}
		ksort($headers);
		foreach($headers as $name => $value) {
			$rep .= strtolower($name).":".$value."\n";
		}
		
		$rep .= $params["path"];
		
		if(!empty($params["query"])) {
      	  	$t = array();
		  	$q = $params["query"];
			ksort($q);
			
			foreach($q as $key => $value) {
				$t[] = urldecode($key)."=".urldecode($value);
		  	}
			
			$rep .= "?".join($t, "&");
		}
		
		return $rep;
	}

	public function signRequest($url, $secret, $opts = array()) {
		$opts = $this->defaultOpts + $opts;
		
		$uri = parse_url($url);
		$query_values = array();
		parse_str($uri["query"], $query_values);
		
		var_dump($query_values);
		
		$headers = !empty($params["headers"]) ? $params["headers"] : array();
		$method = !empty($params["method"]) ? $params["method"] : "GET";
		
		if (!empty($opts["date"])){
			$date = $opts["date"];
			
			if(!($date instanceof DateTime)) {
				if (is_int($date) || is_numeric($date)) {
					$date = new DateTime("@".$date);
				} else {
					// woah, we've done all we could, let's see what datetime makes of this
					$date = new DateTime($date, new DateTimeZone("UTC"));
				}
			}
			
			$date->setTimezone(new DateTimeZone("UTC"));
		} else {
			$date = new DateTime("now", new DateTimeZone("UTC"));
		}
		$date = $date->format('D, d M y H:i:s')." GMT";
		
		$signature = $this->generateSignature(array(
			"secret" 	=> $secret, 
			"method" 	=> $method, 
			"path" 		=> $uri["path"],
			"date" 		=> $date,
			"nonce" 	=> @$opts["nonce"], # this may or may not be set, supress the warning, this will be checked later
			"query" 	=> $query_values, 
			"headers" 	=> $headers
		));
      	
		if ($opts["query_based"] || true) {
			$auth_params = array_merge($opts["extra_auth_params"], array(
				"date" => $date,
				"signature" => $signature
			));
			
			if (!empty( $opts["nonce"])) {
				$auth_params["nonce"] = $opts["nonce"];
        	}
			
			$query_values[$opts["auth_param"]] = $auth_params;
			
		} else {
			
			$headers[$opts["auth_header"]]   = $opts["auth_header_format"]; // % opts.merge({:signature => signature})
			if (!empty($opts["nonce"])) {
				$headers[$opts["nonce_header"]]  = $opts["nonce"];
      		}
			
			if (!empty($opts["use_alternate_date_header"])) {
				$headers[$opts["use_alternate_date_header"]] = $date;
			} else {
				$headers["Date"] = $date;
			}
		}
		
		list($url) = split("\?", $url); # strip the query string
		$url .= "?".http_build_query($query_values);
		
		if (!empty($uri["fragment"])) {
			$url .= "#".$uri["fragment"];
		}
		 
		return array($headers, $url);
		
	}
	
	protected function generateSignature($params) {
		$secret = $params["secret"];
		unset($params["secret"]);
     	return hash_hmac($this->algorithm, $this->canonicalRepresentation($params), $secret);
	}

	public function signUrl($url, $secret, $opts = array()) {
		$opts["query_based"] = true;
		
		list($headers, $url) = $this->signRequest($url, $secret, $opts);
		return $url;
	}

}
		

$params = array(
    "method" => "GET",
    "date" => "Mon, 20 Jun 2011 12:06:11 GMT",
    "nonce" => "TESTNONCE",
    "path" => "/example",
    "query" => array(
      "foo" => "bar",
      "baz" => "foobared"
    ),
    "headers" => array(
      "Content-Type" => "application/json;charset=utf8",
      "Content-MD5" => "d41d8cd98f00b204e9800998ecf8427e"
	)
);

$signer = new WardenHmacSigner();

#echo $signer->canonicalRepresentation($params);
echo $signer->signUrl("http://www.example.org/foo?example=bar&bar=baz#somewhere", "secret", array("date" => "Mon, 20 Jun 2011 12:06:11 GMT"));

?>