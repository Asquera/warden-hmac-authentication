require_relative 'base'

class Warden::Strategies::HMAC < Warden::Strategies::HMACBase
  
  # Checks that this strategy applies. Tests that the required
  # authentication information was given.
  #
  # @return [Bool] true if all required authentication information is available in the request
  # @see https://github.com/hassox/warden/wiki/Strategies
  def valid?
    valid = auth_info.include? "signature"
    valid = valid && has_timestamp? if check_ttl?
    valid = valid && has_nonce? if nonce_required?
    valid
  end

  # Check that the signature given in the request is valid.
  #
  # @return [Bool] true if the request is valid
  def signature_valid?
    hmac.check_url_signature(request.url, secret)
  end
  
  def auth_info
    params[auth_param] || {}
  end
  
  def signature
    auth_info["hmac"]
  end
  
  def nonce
    auth_info["nonce"] || ""
  end
  
  def request_timestamp
    auth_info["date"] || ""
  end
  
  def request_method
    env['REQUEST_METHOD'].upcase
  end
  
  def params
    request.GET
  end
  
  def headers
    pairs = env.select {|k,v| k.start_with? 'HTTP_'}
        .collect {|pair| [pair[0].sub(/^HTTP_/, '').gsub(/_/, '-'), pair[1]]}
        .sort
     headers = Hash[*pairs.flatten]
     headers   
  end
  
  def retrieve_user
    true
  end
  
    
end

Warden::Strategies.add(:hmac, Warden::Strategies::HMAC)
