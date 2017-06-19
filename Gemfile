source 'http://rubygems.org'

gemspec

group :test do
  if RUBY_VERSION < "1.9"
    gem "nokogiri",   "~> 1.5.0"
    gem "ruby-debug", "~> 0.10.4"
  elsif RUBY_VERSION < "2.0"
    gem "debugger", "~> 1.1"
  else
    gem "byebug",   "~> 2.1.1"
  end
  gem "shoulda",    "~> 2.11"
  gem "rake",       "~> 10"
  gem "mocha",      "~> 0.14",  :require => false
  gem "timecop",    "<= 0.6.0"
  gem "systemu",    "~> 2"
  gem "rspec",      "~> 2"
  gem "test-unit"
end
