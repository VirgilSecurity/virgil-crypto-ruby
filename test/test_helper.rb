require 'virgil/crypto'
require 'minitest/autorun'
require 'minitest/reporters'
require 'envyable'

Envyable.load('./test/data/env.yml')

Minitest::Reporters.use! Minitest::Reporters::DefaultReporter.new

root_path = File.expand_path('../', __FILE__)
Dir[File.join(root_path, 'data/**/*.rb')].each { |f| require f }
