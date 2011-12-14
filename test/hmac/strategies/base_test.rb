require 'hmac/signer'
require 'hmac/strategies/base'
require 'rack/builder'

class DummyStrategy < Warden::Strategies::HMAC::Base
  def valid?
    true
  end
  
  def authenticate!
    success!(retrieve_user)
  end
  
end


Warden::Strategies.add(:dummy, DummyStrategy)


context "retrieving the user" do
  
  setup do
    
    env = {
      "warden" =>  OpenStruct.new({
        :config => {
         :scope_defaults => {
           :default => {
             :hmac => {
               :secret => "secrit",
               :retrieve_user => Proc.new {|strategy|
                 users = {
                   "Testkey" => "Testuser"
                 }
                 users[strategy.params["auth"]["access_key"]]
               }
             }
           }
          } 
        }
      })
    }
    strategy = Warden::Strategies::HMAC::Header.new(env_with_params('/', {"auth[access_key]" => "Testkey"}, env), :default)
  end
  
  asserts(:retrieve_user).equals("Testuser")
  
  
  
end