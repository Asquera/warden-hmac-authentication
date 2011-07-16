require_relative 'base'

class Warden::Strategies::HMAC < Warden::Strategies::HMACBase
  def valid?
    valid = auth_info.include? "signature"
    valid = valid && has_timestamp? if check_ttl?
    valid = valid && has_nonce? if nonce_required?
    valid
  end

  def authenticate!
    if "" == secret.to_s
      debug("authentication attempt with an empty secret")
      return fail!("Cannot authenticate with an empty secret")
    end
    
    if check_ttl? && !timestamp_valid?
      debug("authentication attempt with an invalid timestamp. Given was #{timestamp}, expected was #{Time.now.gmtime}")
      return fail!("Invalid timestamp")  
    end
    
    if hmac.check_url_signature(request.url, secret)
      success!(retrieve_user)
    else
      debug("authentication attempt with an invalid signature.")
      fail!("Invalid token passed")
    end
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
