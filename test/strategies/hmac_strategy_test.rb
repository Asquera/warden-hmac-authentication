require 'strategies/hmac_strategy'
require 'rack/builder'

context "HMAC" do
  
  context "> with a valid secret " do
    app(
      Rack::Builder.new do
        use Rack::Session::Cookie
        use Warden::Manager do |manager|
          manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
          manager.default_scope = :default
          manager.scope_defaults :default, :strategies => [:password, :basic]
          manager.scope_defaults :hmac, :strategies => [:hmac], 
                                         :store => false, 
                                         :hmac => { 
                                           :secret => "secrit",
                                           :algorithm => "md5"
                                         }
        end
      
        run -> env {
          env["warden"].authenticate!(:scope => :hmac)
          [200, {"Content-Length" => "0"}, [""]]
        }
      end.to_app
    ) 

    context "> with a valid signature" do
      setup do
        uri = "http://example.org/?user_id=123"
        signed = HMAC.new('md5').sign_url(uri, 'secrit')
      
        get signed
      end

      asserts(:status).equals(200)
    end
    
    context "> with no signature" do
      setup do
        get "http://example.org/?user_id=123&auth="
      end

      asserts(:status).equals(401)
    end
    
    context "> with an invalid signature" do
      setup do
        get "http://example.org/?user_id=123&auth[signature]=foo"
      end

      asserts(:status).equals(401)
    end
    
  end
  
  context "> with an empty secret " do
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
                                           :secret => "",
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

    context "> with a valid signature" do
      setup do
        uri = "http://example.org/?user_id=123"
        signed = HMAC.new('md5').sign_url(uri, '')
      
        get signed
      end
      
      asserts(:status).equals(401)
      
    end
  end
  
  
  context "> with a proc as secret " do
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
                                           :secret => Proc.new {|strategy|
                                             "secrit"
                                           },
                                           :algorithm => "md5"
                                         }
        end
      
        run -> env {
          env["warden"].authenticate!(:scope => :token)
          [200, {"Content-Length" => "0"}, [""]]
        }
      end.to_app
    )
    
    context "> with a valid signature" do
      setup do
        uri = "http://example.org/?user_id=123"
        signed = HMAC.new('md5').sign_url(uri, 'secrit')
      
        get signed
      end

      asserts(:status).equals(200)
    end
    
    context "> with no signature" do
      setup do
        get "http://example.org/?user_id=123&auth="
      end

      asserts(:status).equals(401)
    end
    
    context "> with an invalid signature" do
      setup do
        get "http://example.org/?user_id=123&auth[signature]=foo"
      end

      asserts(:status).equals(401)
    end
  end
  
  
  context "> using ttls " do
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
                                           :ttl => 300,
                                           :hmac => HMAC
                                         }
        end
      
        run -> env {
          env["warden"].authenticate!(:scope => :token)
          [200, {"Content-Length" => "0"}, [""]]
        }
      end.to_app
    ) 

    context "> without timestamp" do
      setup do
        uri = "http://example.org/?user_id=123"
        signed = HMAC.new('md5').sign_url(uri, 'secrit')
      
        get signed
      end

      asserts(:status).equals(401)
    end
    
    context "> with an expired timestamp " do
      setup do
        uri = "http://example.org/?user_id=123"
        signed = HMAC.new('md5').sign_url(uri, 'secrit', :date => (Time.now - 3000))
      
        get signed
      end

      asserts(:status).equals(401)
    end
    
    context "> with timestamp in the future" do
      setup do
        uri = "http://example.org/?user_id=123"
        signed = uri + "&token=" + HMAC.new('md5').sign_url(uri, 'secrit', :date => (Time.now + 3000))
      
        get signed
      end

      asserts(:status).equals(401)
    end
    
    context "> with valid timestamp slighty in the past" do
      setup do
        uri = "http://example.org/?user_id=123"
        signed = uri + "&token=" + HMAC.new('md5').sign_url(uri, 'secrit', :date => (Time.now - 100))
        get signed
      end

      asserts(:status).equals(200)
    end
    
    context "> with timestamp equal current time" do
      setup do
        uri = "http://example.org/?user_id=123"
        signed = uri + "&token=" + HMAC.new('md5').sign_url(uri, 'secrit', :date => Time.now)
        get signed
      end

      asserts(:status).equals(200)
    end
    
    context "> with timestamp slightly into the future" do
      setup do
        uri = "http://example.org/?user_id=123"
        signed = uri + "&token=" + HMAC.new('md5').sign_url(uri, 'secrit', :date => (Time.now + 5))
        get signed
      end

      asserts(:status).equals(200)
    end
    
  end
    
end


