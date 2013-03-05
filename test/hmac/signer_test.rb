
context "an HMAC object" do

  setup do
    HMAC::Signer.new("md5")
  end

  context "> generating the canonical representation" do

    asserts("representation with nonce"){
      topic.canonical_representation({
        :method => "GET",
        :date => "Mon, 20 Jun 2011 12:06:11 GMT",
        :nonce => "TESTNONCE",
        :path => "/example",
        :query => {
          "foo" => "bar",
          "baz" => "foobared"
        }
      })
    }.equals("GET\ndate:Mon, 20 Jun 2011 12:06:11 GMT\nnonce:TESTNONCE\n/example?baz=foobared&foo=bar")

    asserts("representation with headers"){
      topic.canonical_representation({
        :method => "GET",
        :date => "Mon, 20 Jun 2011 12:06:11 GMT",
        :nonce => "TESTNONCE",
        :path => "/example",
        :query => {
          "foo" => "bar",
          "baz" => "foobared"
        },
        :headers => {
          "Content-Type" => "application/json;charset=utf8",
          "Content-MD5" => "d41d8cd98f00b204e9800998ecf8427e"
        }
      })
    }.equals("GET\ndate:Mon, 20 Jun 2011 12:06:11 GMT\nnonce:TESTNONCE\ncontent-md5:d41d8cd98f00b204e9800998ecf8427e\ncontent-type:application/json;charset=utf8\n/example?baz=foobared&foo=bar")

  end

  context "> generating the signature for a request" do

    setup do
      topic.sign_request("http://example.org?foo=bar&baz=foobar", "secret", :date => "Mon, 20 Jun 2011 12:06:11 GMT", :nonce => "TESTNONCE")
    end

    context "> resulting headers" do

      setup do
        topic[0]
      end

      asserts("date header") {topic["Date"]}.equals("Mon, 20 Jun 2011 12:06:11 GMT")
      asserts("nonce header") {topic["X-HMAC-Nonce"]}.equals("TESTNONCE")
      asserts("authorization header") {topic["Authorization"]}.equals("HMAC b2c5c7242f664ce18828f108452b437b")

    end

    asserts("resulting url is") {topic[1]}.equals("http://example.org?foo=bar&baz=foobar")
    asserts("query parameter order does not matter") do
      headers, url = * HMAC::Signer.new("md5").sign_request("http://example.org?baz=foobar&foo=bar", "secret", :date => "Mon, 20 Jun 2011 12:06:11 GMT", :nonce => "TESTNONCE")
      headers["Authorization"] == topic[0]["Authorization"]
    end

  end

  context "> generating the signature for a POST request" do

    setup do
      topic.sign_request("http://example.org?foo=bar&baz=foobar", "secret", :method=>"POST", :date => "Mon, 20 Jun 2011 12:06:11 GMT")
    end

    context "> resulting headers" do

      setup do
        topic[0]
      end

      asserts("authorization header") {topic["Authorization"]}.equals("HMAC 655e73744ab08302726f9e8def685cca")

    end

  end

  context "> generating the signature while ignoring some params" do
    helper(:signer) { HMAC::Signer.new('md5') }

    setup do
      signer.sign_request("http://example.org?foo=bar&baz=foobar", "secret", :date => "Mon, 20 Jun 2011 12:06:11 GMT", :ignore_params => [:baz])
    end

    asserts("authorization header") { topic[0]["Authorization"] }.equals {
      signer.sign_request("http://example.org?foo=bar", "secret", :date => "Mon, 20 Jun 2011 12:06:11 GMT", :ignore_params => [:baz])[0]["Authorization"]
    }

  end

  context "signing a url" do
    setup do
      topic.sign_url("http://example.org?foo=bar&baz=foobar", "secret", :date => "Mon, 20 Jun 2011 12:06:11 GMT", :nonce => "TESTNONCE")
    end

    asserts("base url") {topic.split("?")[0]}.equals("http://example.org")
    asserts("parameters") {  Rack::Utils.parse_query(topic.split("?")[1]) }.equals({
      "foo"         => "bar",
      "baz"         => "foobar",
      "auth[date]"  =>"Mon, 20 Jun 2011 12:06:11 GMT",
      "auth[signature]"=>"b2c5c7242f664ce18828f108452b437b",
      "auth[nonce]"=>"TESTNONCE"
    })

  end

  context "signing a url without query parameters" do
    setup do
      topic.sign_url("http://example.org/example.html", "secret", :date => "Mon, 20 Jun 2011 12:06:11 GMT", :nonce => "TESTNONCE")
    end

    asserts("base url") {topic.split("?")[0]}.equals("http://example.org/example.html")
    asserts("parameters") {  Rack::Utils.parse_query(topic.split("?")[1]) }.equals({
      "auth[date]"  =>"Mon, 20 Jun 2011 12:06:11 GMT",
      "auth[signature]"=>"b0287a82bc0d36aef01dd8094c2e2814",
      "auth[nonce]"=>"TESTNONCE"
    })

  end

  context "signing a url with extra auth parameters" do
    setup do
      topic.sign_url("http://example.org/example.html", "secret", :date => "Mon, 20 Jun 2011 12:06:11 GMT", :nonce => "TESTNONCE", :extra_auth_params => {:access_key_id => "KEY1"})
    end

    asserts("base url") {topic.split("?")[0]}.equals("http://example.org/example.html")
    asserts("parameters") {  Rack::Utils.parse_query(topic.split("?")[1]) }.equals({
      "auth[date]"  =>"Mon, 20 Jun 2011 12:06:11 GMT",
      "auth[signature]"=>"b0287a82bc0d36aef01dd8094c2e2814",
      "auth[nonce]"=>"TESTNONCE",
      "auth[access_key_id]" => "KEY1"
    })

  end

  context "signing a url with a fragment" do
    setup do
      topic.sign_url("http://www.example.org/foo?example=bar&bar=baz#somewhere", "secret", :date => "Mon, 20 Jun 2011 12:06:11 GMT")
    end

    asserts("base url") {topic.split("?")[0]}.equals("http://www.example.org/foo")
    asserts("parameters") {  Rack::Utils.parse_query(topic.split("?")[1].split("#")[0]) }.equals({
      "example" => "bar",
      "bar" => "baz",
      "auth[date]"  =>"Mon, 20 Jun 2011 12:06:11 GMT",
      "auth[signature]"=>"4b6c1ea41fbb1c83010ebabbbd6f98e6"
    })
    asserts("fragment") {topic.split("#")[1]}.equals("somewhere")

  end

  asserts("checking a url_signature") { topic.validate_url_signature("http://example.org?baz=foobar&foo=bar&auth[date]=Mon%2C%2020%20Jun%202011%2012%3A06%3A11%20GMT&auth[signature]=b2c5c7242f664ce18828f108452b437b&auth[nonce]=TESTNONCE", "secret") }
  denies("checking an invalid url_signature") { topic.validate_url_signature("http://example.org?baz=foobar&foo=bar&auth[date]=Mon%2C%2020%20Jun%202011%2012%3A06%3A11%20GMT&auth[signature]=AAc5c7242f664ce18828f108452b437b&auth[nonce]=TESTNONCE", "secret") }

  denies("checking a url without auth parameters in query string") { topic.validate_url_signature("http://example.org?foo=bar", "secret") }
  denies("checking a url without query string") { topic.validate_url_signature("http://example.org", "secret") }
end
