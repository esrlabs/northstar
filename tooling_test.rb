# frozen_string_literal: true

require_relative 'tooling'
require 'test/unit'

class TestVersionList < Test::Unit::TestCase
  def test_update_version_list
    require 'tempfile'
    Tempfile.create do |f|
      versions = [{ 'name' => 'crashing', 'version' => '0.0.1' }, { 'name' => 'hello', 'version' => '0.0.2' }]
      f.write versions.to_yaml
      f.close
      update_version_list(f.path, 'hello', '0.1.0')
      update_version_list(f.path, 'new guy', '0.1.0')

      updated_versions = YAML.load_file(f)
      assert_equal(updated_versions.length, 3)
      new_hello = updated_versions.select { |elem| elem['name'] == 'hello' }.first
      assert_equal('0.1.0', new_hello['version'])
    end
  end

  def test_create_version_list
    require 'tempfile'
    path = nil
    Tempfile.create do |f|
      path = f.path
    end

    update_version_list(path, 'hello', '0.1.0')
    update_version_list(path, 'new guy', '0.1.0')

    versions = YAML.load_file(path)
    assert_equal(versions.length, 2)
    new_hello = versions.select { |elem| elem['name'] == 'hello' }.first
    assert_equal('0.1.0', new_hello['version'])
  end

  def test_path_trail
    path = '/tmp'
    trail = path_trail path
    assert_equal(1, trail.length)
    assert_equal('/tmp', trail[0])

    # multi part path
    path = '/tmp/abc/foo'
    trail = path_trail path
    assert_equal(3, trail.length)
    assert_equal('/tmp/abc/foo', trail[0])
    assert_equal('/tmp/abc', trail[1])
    assert_equal('/tmp', trail[2])
  end
end
