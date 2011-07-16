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
      
end

Warden::Strategies.add(:hmac, Warden::Strategies::HMAC)
