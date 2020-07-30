# frozen_string_literal: true

require 'yaml'
require 'tmpdir'
require 'open3'
require 'securerandom'
require 'digest'
require 'rbnacl' # gem install rbnacl
require 'base64'
require 'zip' # gem install rubyzip
require 'fileutils'

def info(content)
  require 'colored'
  puts("#{'INFO'.green}: #{content}")
end

#---------------------------------------------------------------------------------
# NPK
#---------------------------------------------------------------------------------

def unhex(input)
  [input.gsub(' ', '')].pack('H*')
end

def hex(input)
  input.unpack1('H*')
end

def sha256(input)
  RbNaCl::Hash.sha256(input)
end

def round_to_multiple(number, size)
  remainder = number % size
  remainder == 0 ? number : number + size - remainder
end

def shell(cmd, verbose = false)
  if verbose
    Rake.sh cmd
  else
    require 'open3'
    _stdout_str, error_str, status = Open3.capture3(cmd)
    unless status.success?
      warn error_str
      raise 'did not work'
    end
  end
end

def calc_hash_level_offsets(image_size, block_size, digest_size)
  level_offsets = []
  level_sizes = []
  tree_size = 0

  num_levels = 0
  size = image_size
  while size > block_size
    num_blocks = (size + block_size - 1) / block_size
    level_size = round_to_multiple(num_blocks * digest_size, block_size)

    level_sizes << level_size
    tree_size += level_size
    num_levels += 1

    size = level_size
  end

  (0...num_levels).each do |n|
    offset = 0
    ((n + 1)...num_levels).each do |m|
      offset += level_sizes[m]
    end
    level_offsets << offset
  end

  [level_offsets, tree_size]
end

def generate_hash_tree(image, image_size, block_size, salt, hash_level_offsets, tree_size)
  hash_ret = [''].pack("a#{tree_size}")
  hash_src_offset = 0
  hash_src_size = image_size
  level_num = 0
  while hash_src_size > block_size
    level_output_list = []
    remaining = hash_src_size
    while remaining > 0
      hasher = Digest::SHA256.new
      hasher.update(salt)

      if level_num == 0
        image.seek(hash_src_offset + hash_src_size - remaining)
        data = image.read([remaining, block_size].min)
      else
        offset = hash_level_offsets[level_num - 1] + hash_src_size - remaining
        data = hash_ret[offset, block_size]
      end
      hasher.update(data)

      remaining -= data.length
      hasher.update([''].pack("a#{block_size - data.length}")) if data.length < block_size
      level_output_list << hasher.digest
    end

    level_output = level_output_list.join

    padding_needed = (round_to_multiple(level_output.length, block_size) - level_output.length)
    level_output += [''].pack("a#{padding_needed}")

    offset = hash_level_offsets[level_num]
    hash_ret[offset, level_output.length] = level_output

    hash_src_size = level_output.length
    level_num += 1
  end

  [sha256(salt + level_output), hash_ret]
end

def path_trail(p)
  require 'pathname'
  parts = Pathname(p).each_filename.to_a
  trail = parts.each_with_object([[], '/']) do |x, acc|
    prev_path = acc[1]
    next_path = File.join(prev_path, x)
    acc[0].unshift next_path
    acc[1] = next_path
  end
  trail[0]
end

def create_npk(src_dir, npk, manifest, arch_dir, pack_config)
  has_resources = !manifest['resources'].nil?
  is_resource_container = manifest['init'].nil?
  arch = manifest['arch']
  version = manifest['version']
  Dir.mktmpdir do |tmpdir|
    # Copy root
    root_src = "#{src_dir}/root"

    tmp_root = if is_resource_container
                 "#{tmpdir}/root/#{version}"
               else
                 "#{tmpdir}/root"
               end
    FileUtils.mkdir_p(tmp_root, :verbose => false) unless Dir.exist? tmp_root
    Dir["#{root_src}/*"].each { |entry| FileUtils.cp_r(entry, tmp_root, verbose: true) }
    # FileUtils.cp_r(root_src, tmpdir, :verbose => true) if Dir.exist? root_src

    folder_to_package = "#{tmpdir}/root"

    # Copy arch specific root
    Dir.glob("#{arch_dir}/*").each { |f| FileUtils.cp_r(f, tmp_root, :verbose => true) }

    # Write manifest
    File.write("#{tmpdir}/manifest.yaml", manifest.to_yaml)

    fsimg = "#{tmpdir}/fs.img"

    pseudofiles = []
    unless is_resource_container
      pseudofiles << ['/tmp', 444]
      pseudofiles << ['/proc', 444]
      pseudofiles << ['/dev', 444]
      pseudofiles << ['/sys', 444]
      pseudofiles << ['/data', 777]

      # The list of pseudofiles is target specific.
      # Add /lib and lib64 on Linux systems.
      # Add /system on Android.
      case arch
      when 'aarch64-unknown-linux-gnu', 'x86_64-unknown-linux-gnu'
        pseudofiles << ['/lib', 444]
        pseudofiles << ['/lib64', 444]
      when 'aarch64-linux-android'
        pseudofiles << ['/system', 444]
      end
    end

    if has_resources
      manifest['resources'].each do |res|
        # in order to support mountpoints with multiple path segments, we need to call mksquashfs multiple times:
        # e.gl to support res/foo in our image, we need to add /res/foo AND /res
        # ==> mksquashfs ... -p "/res/foo d 444 1000 1000"  -p "/res d 444 1000 1000"
        trail = path_trail res['mountpoint']
        trail.each { |part| pseudofiles << [part, 555] }
      end
    end

    # Create squashfs filesystem image
    require 'os'
    pseudofiles = pseudofiles.map do |d|
      "-p '#{d[0]} d #{d[1]} #{pack_config.uid} #{pack_config.gid}'"
    end.join(' ')
    # TODO: The compression algorithm should be target and not host specific!
    squashfs_comp = OS.linux? ? 'gzip' : 'zstd'
    shell "mksquashfs #{folder_to_package} #{fsimg} -all-root -comp #{squashfs_comp} -no-progress -info #{pseudofiles}"
    raise 'mksquashfs failed' unless File.exist? fsimg

    filesystem_size = File.size(fsimg)

    # Append verity header and hash tree to filesystem image
    verity_hash = nil
    digest_size = 32
    block_size = 4096
    if filesystem_size % block_size != 0
      raise "Filesystem size (#{filesystem_size}) not multiple of block size (#{block_size})"
    end # or pad?

    data_blocks = filesystem_size / block_size
    uuid = SecureRandom.uuid
    salt = SecureRandom.bytes(digest_size)
    hash_level_offsets, tree_size = calc_hash_level_offsets(filesystem_size, block_size, digest_size)
    File.open(fsimg, 'a+b') do |file|
      verity_hash, hash_tree = generate_hash_tree(file, filesystem_size, block_size, salt, hash_level_offsets, tree_size)

      file.seek(filesystem_size)
      file << ['verity', 1, 1, uuid.gsub('-', ''), 'sha256', 4096, 4096, data_blocks, 32, salt, ''].pack('a8 L L H32 a32 L L Q S x6 a256 a3752')
      file << hash_tree
    end

    # Create hashes YAML
    manifest = IO.binread("#{tmpdir}/manifest.yaml")
    manifest_hash = sha256(manifest)
    fs_hash = sha256(IO.binread(fsimg))
    hashes = +''"manifest.yaml:
  hash: #{hex(manifest_hash)}
fs.img:
  hash: #{hex(fs_hash)}
  verity-hash: #{hex(verity_hash)}
  verity-offset: #{filesystem_size}
"''

    # Sign hashes
    signature = Base64.strict_encode64(pack_config.signing_key.sign(hashes))

    signatures = hashes
    signatures << "---\n"
    signatures << "key: #{pack_config.key_id}\n"
    signatures << "signature: #{signature}\n"

    # Create ZIP
    Zip::OutputStream.open(npk) do |stream|
      stream.put_next_entry('signature.yaml', nil, nil, Zip::Entry::STORED)
      stream.write signatures

      stream.put_next_entry('manifest.yaml', nil, nil, Zip::Entry::STORED)
      stream.write manifest

      offset = 43 + manifest.length + 44 + signatures.length + 36 # stored
      padding = (offset / 4096 + 1) * 4096 - offset

      # store uncompressed to support mounting without extracting
      # store at content offset 4096 for direct IO loopback support
      extra = [''].pack("a#{padding}")
      stream.put_next_entry('fs.img', nil, extra, Zip::Entry::STORED)
      stream.write IO.binread(fsimg)
    end

    raise('Alignment failed') unless IO.binread(npk, 4, 4096) == 'hsqs'
  end
end

class PackageConfig
  attr_accessor :uid, :gid, :version, :fstype, :key_id, :signing_key
  def initialize(uid, gid, key_dir, key_id)
    @uid = uid
    @gid = gid
    @key_id = key_id
    signing_key_seed = IO.binread("#{File.join(key_dir, key_id)}.key")
    @signing_key = RbNaCl::SigningKey.new(signing_key_seed)
  end
end

# Create an NPK package
# Params:
# +arch+:: achitecture for which this package will be built
#          e.g. aarch64-linux-android, aarch64-unknown-linux-gnu, x86_64-unknown-linux-gnu
# +arch_dir+:: directory where the architecture specific content is to be found
# +src_dir+:: directory where non-architecture specific content is found
# +out_dir+:: where the npk should be packaged to (usually the registry directory)
def create_arch_package(arch, arch_dir, src_dir, out_dir, pack_config)
  # Load manifest
  manifest = YAML.load_file("#{src_dir}/manifest.yaml")
  manifest['arch'] = arch
  name = manifest['name']
  version = manifest['version']
  info "Packing #{src_dir} (#{arch})"

  npk = "#{out_dir}/#{name}-#{arch}-#{version}.npk"

  # TODO: do this seperatly
  # Remove existing containers
  Dir.glob("#{out_dir}/#{name}-#{arch}-*").each { |c| FileUtils.rm(c, :verbose => false) }

  create_npk(src_dir, npk, manifest, arch_dir, pack_config)

  # Update/Create version list
  version_info_path = File.join(out_dir, "packages-#{arch}.yaml")
  update_version_list(version_info_path, name, version)
end

def update_version_list(version_file, name, new_version)
  versions = if File.exist?(version_file)
               YAML.load_file(version_file)
             else
               []
             end
  if versions.any? { |x| x['name'] == name }
    versions.map do |n|
      if n['name'] == name
        n['version'] = new_version
      else
        n
      end
    end
  else
    versions << { 'name' => name, 'version' => new_version }
  end
  versions.each { |r| r.transform_keys(&:to_s) }
  File.write(version_file, versions.to_yaml)
end

def inspect_npk(pkg, show_files = false)
  require 'colored'
  s = "Inspecting #{File.basename(pkg, '.npk').green}"
  puts(('-' * s.length).green)
  puts s
  puts(('-' * s.length).green)
  Dir.mktmpdir do |tmpdir|
    cp_r pkg, tmpdir, :verbose => false
    cd tmpdir, :verbose => false do
      Zip::File.open(pkg) do |zip_file|
        zip_file.each do |f|
          f_path = File.join('extracted', f.name)
          FileUtils.mkdir_p(File.dirname(f_path))
          zip_file.extract(f, f_path) unless File.exist?(f_path)
        end
        cd 'extracted', :verbose => false do
          if show_files
            puts `tree .`
            if File.exist? 'manifest.yaml'
              puts "#{'Manifest'.yellow}:\n#{File.read('manifest.yaml')}"
            end
            if File.exist? 'signature.yaml'
              puts "#{'Signature'.yellow}:\n#{File.read('signature.yaml')}"
            end
          end
          Dir['*.img'].each do |file|
            puts "#{'squashFS-image'.yellow}: #{file}"
            sh "unsquashfs -l #{file}", verbose: false
          end
        end
      end
    end
  end
end
