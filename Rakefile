require "bundler/gem_tasks"
require 'rake/extensiontask'
require 'rake/testtask'
require 'mkmf'

Rake::TestTask.new do |t|
  t.libs << 'test'
  t.test_files = FileList['test/**/*_test.rb']
end

task :default => :test


