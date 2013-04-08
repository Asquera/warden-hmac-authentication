require 'faraday'
require 'faraday/request/hmac'
require 'riot/rr'

class DummyApp
  attr_accessor :env

  def call(env)
    @env = env
  end

  def reset
    @env = nil
  end
end


context "the faraday middleware" do

  setup do
    Timecop.freeze Time.gm(2011, 7, 1, 20, 28, 55)
  end

  teardown do
    Timecop.return
  end

  context "> using header-based auth" do
    setup do
      m = Faraday::Request::Hmac.new(DummyApp.new, "testsecret")
      m.call({ :request_headers => {}, :url => 'http://www.example.com' })
    end

    asserts("authorization header") {topic[:request_headers]["Authorization"]}.equals("HMAC 539263f4f83878a4917d2f9c1521320c28b926a9")
    asserts("date header") {topic[:request_headers]["Date"]}.equals("Fri,  1 Jul 2011 20:28:55 GMT")
    asserts("query values") {topic[:url].query}.nil

    context "> using a different auth header format" do
      setup do
        m = Faraday::Request::Hmac.new(DummyApp.new, "testsecret", {:auth_key => 'TESTKEYID', :auth_header_format => '%{auth_scheme} %{auth_key} %{signature}'})
        m.call({ :request_headers => {}, :url => 'http://www.example.com' })
      end

      asserts("authorization header") {topic[:request_headers]["Authorization"]}.equals("HMAC TESTKEYID 539263f4f83878a4917d2f9c1521320c28b926a9")
      asserts("date header") {topic[:request_headers]["Date"]}.equals("Fri,  1 Jul 2011 20:28:55 GMT")
      asserts("query values") {topic[:url].query}.nil
    end

  end

  context "> using query-based auth" do
    setup do
      m = Faraday::Request::Hmac.new(DummyApp.new, "testsecret", {:query_based => true, :extra_auth_params => {"auth_key" => "TESTKEYID"}})
      m.call({ :request_headers => {}, :url => 'http://www.example.com' })
    end

    asserts("authorization header") {topic[:request_headers]["Authorization"]}.nil
    asserts("date header") {topic[:request_headers]["Date"]}.nil

    context "> query values" do

      setup do
        Rack::Utils.parse_nested_query(topic[:url].query)
      end

      asserts("auth date") {topic["auth"]["date"]}.equals("Fri,  1 Jul 2011 20:28:55 GMT")
      asserts("auth_key") {topic["auth"]["auth_key"]}.equals("TESTKEYID")
      asserts("auth signature") {topic["auth"]["signature"]}.equals("539263f4f83878a4917d2f9c1521320c28b926a9")
    end

  end


  context "> integration test" do
    setup do
      con = Faraday.new(:url => "http://example.com/") do |builder|
        builder.headers['X-Public-Key'] = 'TESTPUBLIC'
        builder.headers['Content-MD5'] = '539263f4f83878a4917d2f9c1521320c28b926a9'

        builder.use Faraday::Request::Hmac, 'TESTKEYID'
        builder.adapter :test do |stub|
          stub.get('/') do |env|
            [200, {}, ""]
          end

          stub.post('/') do |env|
            [200, {}, ""]
          end
        end
      end
    end

    asserts("does not raise exception") { topic.get('/') }
    asserts("passes method properly") {
      representation = nil
      any_instance_of(HMAC::Signer) do |signer|
        proxy(signer).canonical_representation do |r|
          representation = r
        end
      end
      topic.post('/')
      representation[0, 4] == 'POST'
    }
  end

end
