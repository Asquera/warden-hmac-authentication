source "https://rubygems.org"

group :documentation do
  gem "rdiscount", :group => "documentation", :platforms => [:ruby_19]    # added here since jruby does not like rdiscount
  gem "yard", :group => "documentation", :platforms => [:ruby_19]         # added here since jruby does not like rdiscount
end

gem "jruby-openssl", :platforms => [:jruby]    

gem "faraday", :group => :development

gemspec
