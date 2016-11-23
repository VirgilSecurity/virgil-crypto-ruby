require 'virgil/crypto'

require 'minitest/autorun'
require 'minitest/reporters'

Minitest::Reporters.use! Minitest::Reporters::DefaultReporter.new

root_path = File.expand_path('../', __FILE__)
Dir[File.join(root_path, 'support/**/*.rb')].each { |f| require f }
