
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

  asserts("signing a url") do
    topic.sign_url("http://example.org?foo=bar&baz=foobar", "secret", :date => "Mon, 20 Jun 2011 12:06:11 GMT", :nonce => "TESTNONCE")
  end.equals("http://example.org?baz=foobar&foo=bar&auth[date]=Mon%2C%2020%20Jun%202011%2012%3A06%3A11%20GMT&auth[signature]=b2c5c7242f664ce18828f108452b437b&auth[nonce]=TESTNONCE")
  
  asserts("signing a url without query parameters") { topic.sign_url("http://example.org/example.html", "secret", :date => "Mon, 20 Jun 2011 12:06:11 GMT", :nonce => "TESTNONCE") }.equals("http://example.org/example.html?auth[date]=Mon%2C%2020%20Jun%202011%2012%3A06%3A11%20GMT&auth[signature]=b0287a82bc0d36aef01dd8094c2e2814&auth[nonce]=TESTNONCE")
  asserts("signing a url with extra auth parameters")  { topic.sign_url("http://example.org/example.html", "secret", :date => "Mon, 20 Jun 2011 12:06:11 GMT", :nonce => "TESTNONCE", :extra_auth_params => {:access_key_id => "KEY1"}) }.equals("http://example.org/example.html?auth[date]=Mon%2C%2020%20Jun%202011%2012%3A06%3A11%20GMT&auth[signature]=b0287a82bc0d36aef01dd8094c2e2814&auth[access_key_id]=KEY1&auth[nonce]=TESTNONCE")  
    
  asserts("checking a url_signature") { topic.validate_url_signature("http://example.org?baz=foobar&foo=bar&auth[date]=Mon%2C%2020%20Jun%202011%2012%3A06%3A11%20GMT&auth[signature]=b2c5c7242f664ce18828f108452b437b&auth[nonce]=TESTNONCE", "secret") }
  denies("checking an invalid url_signature") { topic.validate_url_signature("http://example.org?baz=foobar&foo=bar&auth[date]=Mon%2C%2020%20Jun%202011%2012%3A06%3A11%20GMT&auth[signature]=AAc5c7242f664ce18828f108452b437b&auth[nonce]=TESTNONCE", "secret") }
  
  asserts("signing a url with a fragment") {topic.sign_url("http://www.example.org/foo?example=bar&bar=baz#somewhere", "secret", :date => "Mon, 20 Jun 2011 12:06:11 GMT")}.equals("http://www.example.org/foo?bar=baz&example=bar&auth[date]=Mon%2C%2020%20Jun%202011%2012%3A06%3A11%20GMT&auth[signature]=4b6c1ea41fbb1c83010ebabbbd6f98e6#somewhere")
  
end