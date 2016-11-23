require "bundler/gem_tasks"
require 'rake/extensiontask'
require 'rake/testtask'

Rake::ExtensionTask.new('native')

Rake::TestTask.new do |t|
    t.libs << 'test'
    t.test_files = FileList['test/**/*_test.rb']
end

task :default => :test
