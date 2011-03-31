require 'hmac_strategy'
require 'rack/builder'

context "HMAC" do
  app(
    Rack::Builder.new do
      use Rack::Session::Cookie
      use Warden::Manager do |manager|
        manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
        manager.default_scope = :default
        manager.scope_defaults :default, :strategies => [:password, :basic]
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
      
      run -> env {
        env["warden"].authenticate!(:scope => :token)
        [200, {"Content-Length" => "0"}, [""]]
      }
    end.to_app
  ) 

  context "app" do
    setup do
      uri = "http://example.org/?user_id=123"
      signed = uri + "&token=" + HMAC.new('secrit','md5').generate_signature(uri)
      
      get signed
    end

    asserts(:status).equals(200)
  end
end
