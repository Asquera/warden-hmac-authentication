# HMAC

This gem provides a tiny HMAC implementation along with a warden strategy to us it.

## HMAC usage

    h = HMAC.new('secret', 'md5')
    h.generate_signature('http://example.com/?foo=bar')
    
If you want to generate the signature for a signed URL, pass the parameter used for the token:

    h = HMAC.new('secret', 'md5')
    h.generate_signature('http://example.com/?foo=bar&token=123', 'token')
    
## Warden strategy usage

Configure the HMAC warden strategy:

    use Warden::Manager do |manager|
      manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
      # other scopes
      manager.scope_defaults :token, :strategies => [:hmac], 
                                     :store => false, 
                                     :hmac => { 
                                       :params => ["user_id"],
                                       :token => "token",
                                       :secret => "secrit",
                                       :algorithm => "md5",
                                       :hmac => HMAC
                                     }
    end

`params` allows you to specify parameters the request must contain, `token` is the name of the token parameter, `secret` and `algorithm` allow you to specify
the secret and algorithm used for the HMAC algorithm. `hmac` expects a class that implements the HMAC algorithm. It is instantiated on each request.

If you want to retrieve the secret and token using a different strategy, extend the HMAC strategy:

    class Warden::Strategies::HMAC < Warden::Strategies::Base
      def retrieve_user
        User.get(request[:user_id])
      end
      
      def secret
        retrieve_user.secret
      end
    end

The configured secret may also be a proc that retrieves a given secret. The proc must return a string in all cases. The strategy itself is passed as the only parameter
to the given proc and allows access to the full rack env.


    use Warden::Manager do |manager|
      manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
      # other scopes
      manager.scope_defaults :token, :strategies => [:hmac], 
                                     :store => false, 
                                     :hmac => { 
                                       :params => ["user_id"],
                                       :token => "token",
                                       :secret => Proc.new {|strategy|
                                         "secret"
                                       },
                                       :algorithm => "md5",
                                       :hmac => HMAC
                                     }
    end