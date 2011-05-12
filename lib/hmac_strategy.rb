require 'hmac'
require 'warden'

class Warden::Strategies::HMAC < Warden::Strategies::Base
  def valid?
    config[:params].all? { |p| params.include?(p.to_s) } &&
    params.include?(config[:token])
  end

  def authenticate!
    given = params[config[:token]]
    
    if "" == secret.to_s
      fail!("Cannot authenticate with an empty secret")
    end
    
    expected = hmac.generate_signature(request.url, secret, token)

    if given == expected
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
    
    def secret
      @secret ||= config[:secret].respond_to?(:call) ? config[:secret].call(self) : config[:secret]
    end
end

Warden::Strategies.add(:hmac, Warden::Strategies::HMAC)
