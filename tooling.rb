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
  input.unpack('H*').first
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

class PackageInfo
  attr_accessor :architecture, :name, :version
  def initialize(arch, name, version)
    @architecture = arch
    @name = name
    @version = version
  end
end

def pack_containers(registry, container_sources, key_directory, key_name, fstype, uid, gid)
  signing_key = IO.binread("#{File.join(key_directory, key_name)}.key")
  packages = []

  Dir.glob("#{container_sources}/**/*")
     .filter { |d| File.exist?(File.join(d, 'manifest.yaml')) }
     .sort
     .each do |src_dir|
    packages += pack(src_dir, registry, signing_key, key_name, fstype, uid, gid)
  end
  Dir.glob("#{registry}/*.yaml").each { |f| rm f }

  # Create version list
  packages.each do |p|
    File.open("#{registry}/packages-#{p.architecture}.yaml", 'a') do |f|
      f.puts "{ 'name' => #{p.name}, 'version' => #{p.version} }"
    end
  end
end

def pack(src_dir, registry, signing_key, key_name, fstype, uid, gid)
  packages = []
  Dir.glob("#{src_dir}/root-*").each do |arch_dir|
    arch = arch_dir.gsub(%r{.*/root-}, '')
    # Load manifest
    manifest = YAML.load_file("#{src_dir}/manifest.yaml")
    name = manifest['name']
    version = manifest['version']
    info "Packing #{src_dir} (#{arch})"
    uid = 1000
    gid = 1000

    Dir.mktmpdir do |tmpdir|
      # Copy root
      root = "#{src_dir}/root"
      FileUtils.cp_r(root, tmpdir, :verbose => false) if Dir.exist? "#{src_dir}/root"
      FileUtils.mkdir_p("#{tmpdir}/root", :verbose => false) unless Dir.exist? "#{tmpdir}/root"

      # Copy arch specific root
      Dir.glob("#{arch_dir}/*").each { |f| FileUtils.cp_r(f, "#{tmpdir}/root", :verbose => false) }

      # Write manifest
      manifest['arch'] = arch
      File.open("#{tmpdir}/manifest.yaml", 'w') { |f| f.write(manifest.to_yaml) }

      # Remove existing containers
      Dir.glob("#{registry}/#{name}-#{arch}-*").each { |c| FileUtils.rm(c, :verbose => false) }

      npk = "#{registry}/#{name}-#{arch}-#{version}.npk"
      root = "#{tmpdir}/root"
      fsimg = "#{tmpdir}/fs.img"

      # The list of pseudofiles is target specific.
      # Add /lib and lib64 on Linux systems.
      # Add /system on Android.
      pseudofiles = [['/tmp', 444], ['/proc', 444], ['/dev', 444], ['/sys', 444]]
      pseudofiles = case arch
      when 'aarch64-unknown-linux-gnu', 'x86_64-unknown-linux-gnu'
        pseudofiles += [['/lib', 444], ['/lib64', 444]]
      when 'aarch64-linux-android'
        pseudofiles += [['/system', 444], ['/data', 777]]
      else
        pseudofiles
      end

      # Create filesystem image
      if fstype == 'squashfs'
        require 'os'
        pseudofiles = pseudofiles.map { |d| "-p '#{d[0]} d #{d[1]} #{uid} #{gid}'" }.join(' ')
        # TODO: The compression algorithm should be target and not host specific!
        squashfs_comp = OS.linux? ? 'gzip' : 'zstd'
        shell "mksquashfs #{root} #{fsimg} -all-root -comp #{squashfs_comp} -no-progress -info #{pseudofiles}"
        raise 'mksquashfs failed' unless File.exist? fsimg
      elsif fstype == 'ext4'
        pseudofiles.each { |d| FileUtils.mkdir_p("#{root}#{d[0]}") unless Dir.exist? "#{root}#{d[0]}" }

        # system("chmod", "-R", "a-w,a+rX", root) or raise "chmod failed"
        # system("chown", "-R", "0:0", root) or raise # only works as root
        blocks = `du -ks #{root}`.split.first.to_i # rough, too big, estimate
        shell("mke2fs -q -b 4096 -t ext4 -v -m 0 -d #{root} #{fsimg} #{blocks}")
        e2fsck_output = `e2fsck -f -n #{fsimg}`
        unless e2fsck_output.chomp.split("\n").last =~ %r{(\d+)/\d+ blocks}
          raise "e2fsck failed: #{e2fsck_output}"
        end

        blocks = Regexp.last_match(1).to_i # actual required blocks
        FileUtils.rm_f(fsimg)
        sh("mke2fs  -q -b 4096 -t ext4 -v -m 0 -d #{root} #{fsimg} #{blocks}")

        pseudofiles.each { |d| FileUtils.rmdir("#{root}#{d[0]}") }
      else
        raise "Unknown filesystem: #{fstype}"
      end
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
      signing_key = RbNaCl::SigningKey.new(signing_key)
      signature = Base64.strict_encode64(signing_key.sign(hashes))

      signatures = hashes
      signatures << "---\n"
      signatures << "key: #{key_name}\n"
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

      if fstype == 'squashfs'
        raise('Alignment failed') unless IO.binread(npk, 4, 4096) == 'hsqs'
      end

      packages << PackageInfo.new(arch, name, version)
    end
  end
  packages
end
