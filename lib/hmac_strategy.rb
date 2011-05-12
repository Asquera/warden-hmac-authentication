require 'hmac'
require 'warden'

class Warden::Strategies::HMAC < Warden::Strategies::Base
  def valid?
    valid = config[:params].all? { |p| params.include?(p.to_s) } && params.include?(token)
    valid = valid && params.include?(timestamp_name) if check_ttl?  
    valid
  end

  def authenticate!
    if "" == secret.to_s
      return fail!("Cannot authenticate with an empty secret")
    end
    
    if check_ttl? && !timestamp_valid?
      return fail!("Invalid timestamp")  
    end
    
    if hmac.check_signature(request.url, secret, token)
      success!(retrieve_user)
    else
      fail!("Invalid token passed")
    end
  end
  
  def params
    request.GET
  end
  
  def retrieve_user
    true
  end
  
  private
    def config
      env["warden"].config[:scope_defaults][scope][:hmac]
    end
    
    def hmac
      config[:hmac].new(algorithm)
    end
    
    def algorithm
      config[:algorithm]
    end
    
    def token
      config[:token]
    end
    
    def ttl
      config[:ttl].to_i
    end
    
    def check_ttl?
      !config[:ttl].nil?
    end

    def timestamp_name
      config[:timestamp] || "timestamp"
    end

    def timestamp
      params[timestamp_name].to_i
    end
    
    def timestamp_valid?
      now = (Time.now.gmtime.to_f * 1000).round
      timestamp < (now + clockskew) && timestamp > (now - ttl * 1000)
    end

    def secret
      @secret ||= config[:secret].respond_to?(:call) ? config[:secret].call(self) : config[:secret]
    end
    
    def clockskew
      (config[:clockskew] || 5) * 1000
    end
end

Warden::Strategies.add(:hmac, Warden::Strategies::HMAC)
