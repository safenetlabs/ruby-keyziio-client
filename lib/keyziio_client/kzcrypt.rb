#require_relative 'version.rb'
require 'base64'
require 'openssl'
require 'stringio'
#require_relative 'kzrestclient.rb'
require_relative 'kzheader.rb'

class InvalidKeyException < Exception

end

class KZCrypt
  attr_accessor :keychain_key
  # File crypto operations for Keyziio
  def initialize(rest_client, keychain_key)
    @chunk_length = 1024
    @rest_client = rest_client #KZRestClient.new
    @cipher_algo = 'AES-256-CBC'
    @cipher_block_size = 16
    @header = KZHeader.new
    @mac = nil
    @user_cipher = nil
    @keychain_key = keychain_key
  end

  def _process_file (file_in, file_out, encrypt, key_name=nil)
    key_id = nil
    if not encrypt
      # get the key id from the file itself
      header_length = @header.decode_header(file_in, true)
      key_id = @header.key_id
    end

    # Setup encrypt/decrypt key and mac
    new_key = encrypt
    cipher, key_id = _init_cipher(key_name, key_id, new_key)

    plain_text_length = File.stat(file_in).size
    File.open(file_in, 'rb') do |f_in|
      if not encrypt
        # Check the mac
        if @mac != @header.mac
          raise InvalidKeyException
        end
        f_in.seek(header_length)
      end
      File.open(file_out, 'wb') do |f_out|
        if encrypt
          # create a header
          @header.key_id = key_id
          @header.mac = @mac
          f_out.write(@header.encode())
        end
        bytes_remaining = plain_text_length
        while bytes_remaining > 0
          bytes_to_read = bytes_remaining < @chunk_length ? bytes_remaining : @chunk_length
          data_in = f_in.read(bytes_to_read)
          bytes_remaining -= bytes_to_read
          if encrypt
            f_out.write(_encrypt_chunk(cipher, data_in, bytes_remaining <= 0 ))
          else
            f_out.write(_decrypt_chunk(cipher, data_in, bytes_remaining <= 0 ))
          end
        end
      end
    end
  end

  def _process_buffer (obj_in, encrypt, key_name=nil)
    key_id = nil
    if not encrypt
      # get the key id from the file itself
      header_length = @header.decode_header(obj_in, false)
      key_id = @header.key_id
    end

    # Setup decrypt key and mac
    new_key = encrypt
    cipher, key_id = _init_cipher(key_name, key_id, new_key)

    obj_out = ''
    #plain_text_length = encrypt ? obj_in.bytesize : obj_in[0].bytesize
    plain_text_length = obj_in.bytesize

    if not encrypt
      # Check the mac
      if @mac != @header.mac
        raise InvalidKeyException
      end
      dec_buf = Base64.decode64(obj_in[header_length .. plain_text_length])
    end

    if encrypt
      # create a header
      @header.key_id = key_id
      @header.mac = @mac
      obj_out = @header.encode()
      bytes_remaining = plain_text_length
    else
      bytes_remaining = dec_buf.bytesize
    end

    offset = 0
    enc_out = ''
    while bytes_remaining > 0
      bytes_to_read = bytes_remaining < @chunk_length ? bytes_remaining : @chunk_length
      if not encrypt
        data_in = dec_buf[offset .. bytes_to_read]
      else
        data_in = obj_in[offset .. bytes_to_read]
      end
      offset = offset + bytes_to_read

      bytes_remaining -= bytes_to_read
      if encrypt
        enc_out << _encrypt_chunk(cipher, data_in, bytes_remaining <= 0 )
      else
        obj_out << _decrypt_chunk(cipher, data_in, bytes_remaining <= 0 )
      end
    end
    if encrypt
      obj_out << Base64.encode64(enc_out)
    end
    obj_out
  end

  def _encrypt_chunk (cipher, data_in, is_last_chunk)
    if data_in.length == 0
      return ''
    end
    if is_last_chunk
      pad_length = @cipher_block_size - (data_in.length % @cipher_block_size)
      if pad_length == 0
        pad_length = @cipher_block_size
      end
      data_in += pad_length.chr * pad_length
      return cipher.update(data_in) << cipher.final
    end
    return cipher.update(data_in)
  end

  def _decrypt_chunk (cipher, data_in, is_last_chunk)
    if data_in.length == 0
      return ''
    end
    data_out = cipher.update(data_in)
    if is_last_chunk
      data_out << cipher.final
    end
    return !is_last_chunk ? data_out : data_out[0..-((data_out[-1]).ord + 1)]
  end

  def _init_cipher (key_name, key_id, new_key)
    key, iv, type, id = new_key ? create_and_post_data_key(key_name) : get_data_key(key_id)
    @mac = _make_mac (key)
    cipher = OpenSSL::Cipher.new(type)
    encrypt = new_key
    if encrypt
      cipher.encrypt
    else
      cipher.decrypt
    end
    cipher.iv = iv
    cipher.key = key
    # We take care of padding
    cipher.padding = 0
    return cipher, id
  end

  def _make_mac (raw_key)
    #  Returns a MAC of the keyziio header magic number
    digest = OpenSSL::Digest.new('sha256')
    return OpenSSL::HMAC.hexdigest(digest, raw_key, @header.magic_number)
  end

  def unwrap_key (wrapped_keychain_key, private_key)
    # Decrypt wrapped_keychain_key with the given private key
    begin
      private_key.private_decrypt(wrapped_keychain_key, OpenSSL::PKey::RSA::PKCS1_PADDING)
    rescue OpenSSL::PKey::RSAError
      raise InvalidKeyException
    end
  end

  def create_and_post_data_key (key_name)
    cipher = OpenSSL::Cipher.new(@cipher_algo)
    key = cipher.random_key
    iv = cipher.random_iv

    wrapped_data_key = wrap_data_key(key, iv)
    response = @rest_client.post_data_key(key_name, @cipher_algo, Base64.encode64(wrapped_data_key), Base64.encode64(iv))
    return key, iv, @cipher_algo, JSON.parse(response)['id']
  end

  def get_data_key (key_id)
    response = @rest_client.get_key(key_id)
    # Key is encrypted under the user key, we have to decrypt it
    iv = Base64.decode64(JSON.parse(response)['iv'])
    wrapped_key = Base64.decode64(JSON.parse(response)['key'])
    raw_key = unwrap_data_key(wrapped_key, iv)
    raise InvalidKeyException if(raw_key.nil? or raw_key.size != 32)
    type = JSON.parse(response)['type']

    return raw_key, iv, type, key_id
  end

  def wrap_data_key (key, iv)
    # encrypt data key with the user key
    user_cipher = OpenSSL::Cipher.new(@cipher_algo)
    user_cipher.encrypt
    user_cipher.key = @keychain_key
    user_cipher.iv = iv
    # no padding
    user_cipher.padding = 0

    wrapped_data_key = user_cipher.update(key)
    wrapped_data_key << user_cipher.final
  end

  def unwrap_data_key (wrapped_data_key, iv)
    # decrypt data key with the user key
    user_cipher = OpenSSL::Cipher.new(@cipher_algo)
    user_cipher.decrypt
    user_cipher.key = @keychain_key
    user_cipher.iv = iv
    # no padding
    user_cipher.padding = 0

    data_key = user_cipher.update(wrapped_data_key)
    data_key << user_cipher.final
  end

  def create_key_pair (size)
    # Create an ephemeral key pair for establishing session and acquiring user key
    OpenSSL::PKey::RSA.new size
  end

  def construct_keychain_key (keychain_key_pt1, keychain_key_pt2)
    # XOR given key parts to contruct a key
    @keychain_key = ''.force_encoding 'BINARY'
    # using zip method to combine the strings as byte arrays and then xor elements of
    # the two arrays
    keychain_key_pt1.each_byte.zip(keychain_key_pt2.each_byte) {|a,b| @keychain_key<<(a^b)}
    return Base64.encode64(@keychain_key)

    # # Do the same for iv as well
    # @iv = ''.force_encoding 'BINARY'
    # iv_pt1.each_byte.zip(iv_pt2.each_byte) {|a,b| @iv<<(a^b)}
  end

  def encrypt_file (file_in, file_out, key_name)
    # Encrypts file_in using key_name.  It will create the key if it has to.
    _process_file(file_in, file_out, true, key_name)
  end

  def decrypt_file (file_in, file_out)
    # Decrypts file_in using key_id.  It will create the key if it has to.
    _process_file(file_in, file_out, false)
  end

  def encrypt_buffer (buf_in, key_name)
    # Encrypts buf_in using key_name.  It will create the key if it has to.
    _process_buffer(buf_in, true, key_name)
  end

  def decrypt_buffer (buf_in)
    # Decrypts buf_in using key_id.  It will create the key if it has to.
    _process_buffer(buf_in, false)
  end
end
