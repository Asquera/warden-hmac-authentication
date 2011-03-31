require 'hmac'
require 'warden'

class Warden::Strategies::HMAC < Warden::Strategies::Base
  def valid?
    config[:params].all? { |p| params.include?(p.to_s) } &&
    params.include?(config[:token])
  end

  def authenticate!
    given = params[config[:token]]
    expected = hmac.generate_signature(request.url, token)

    if given == expected
      success!(retrieve_user)
    else
      halt!
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
      config[:hmac].new(secret, algorithm)
    end
    
    def algorithm
      config[:algorithm]
    end
    
    def token
      config[:token]
    end
    
    def secret
      config[:secret]
    end
end

Warden::Strategies.add(:hmac, Warden::Strategies::HMAC)
