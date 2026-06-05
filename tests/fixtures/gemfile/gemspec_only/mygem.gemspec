Gem::Specification.new do |spec|
  spec.name = "mygem"
  spec.version = MyGem::VERSION
  spec.authors = ["Anon"]
  spec.summary = "A synthetic gem for licenseal tests."
  spec.licenses = ["MIT", "Apache-2.0"]
  spec.homepage = "https://example.com/mygem"

  spec.add_dependency "rack", ">= 2.0"
  spec.add_runtime_dependency "puma"
  spec.add_development_dependency "rspec", "~> 3.12"
end
