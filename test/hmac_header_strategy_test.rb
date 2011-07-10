require 'hmac_header_strategy'
require 'rack/builder'

context "header-based auth" do
  
  warden_struct = OpenStruct.new({
    :config => {
     :scope_defaults => {
       :default => {
         :hmac => {
           :secret => "secrit"
         }
       }
      } 
    }
  })
  
  context "> without authorization header" do
    
    setup do
      env = {"warden" => warden_struct}
      strategy = Warden::Strategies::HMACHeader.new(env_with_params('/', {}, env), :default)
    end
    
    denies(:valid?)
    
  end
  
  
  context "> with authorization header but invalid scheme name" do
    
    setup do
      env = {
        "warden" => warden_struct,
        "HTTP_Date" => "Mon, 20 Jun 2011 12:06:11 GMT",
        "HTTP_Authorization" => "Basic foo:bar"}
      strategy = Warden::Strategies::HMACHeader.new(env_with_params('/', {}, env), :default)
    end
    
    denies(:valid?)
    
  end
  
  context "> with authorization header and valid scheme name" do
    
    setup do
      env = {
        "warden" => warden_struct,
        "HTTP_Date" => "Mon, 20 Jun 2011 12:06:11 GMT",
        "HTTP_Authorization" => "HMAC c2ce0f0885378f3e2e4024f505416c78abdd7a4b"}
      strategy = Warden::Strategies::HMACHeader.new(env_with_params('/', {}, env), :default)
    end
    
    asserts(:valid?)
    denies(:timestamp_valid?)
    denies(:authenticate!).equals(:success)
  
    context "> with valid timestamp" do
      setup do
        env = {
          "warden" => warden_struct,
          "HTTP_Date" => Time.now.gmtime.strftime('%a, %e %b %Y %T GMT'),
          "HTTP_Authorization" => "HMAC c2ce0f0885378f3e2e4024f505416c78abdd7a4b"}
        strategy = Warden::Strategies::HMACHeader.new(env_with_params('/', {}, env), :default)
      end

      asserts(:valid?)
      asserts(:timestamp_valid?)
      denies(:authenticate!).equals(:success)
    end
    
    context "> with valid signature" do
      
      setup do
        Timecop.freeze Time.local(2011, 7, 1, 22, 28, 55)
      
        env = {
          "warden" => warden_struct,
          "HTTP_Date" => Time.now.gmtime.strftime('%a, %e %b %Y %T GMT'),
          "HTTP_Authorization" => "HMAC a59456da1f61f86e96622e283780f58b7428c892"}
        strategy = Warden::Strategies::HMACHeader.new(env_with_params('/', {}, env), :default)
      end
      
      teardown do
        Timecop.return
      end

      asserts(:valid?)
      asserts(:timestamp_valid?)
      asserts(:signature).equals("a59456da1f61f86e96622e283780f58b7428c892")
      asserts(:authenticate!).equals(:success)
    end
  
  end
  
  
  
end