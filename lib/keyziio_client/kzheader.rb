#require_relative 'version.rb'

require 'json'
require 'stringio'

class KeyziioDecodeException < Exception
  # File is either not an encrypted keyziio file or does not have a valid header
  def to_s
    return 'File is either not an encrypted keyziio file or does not have a valid header'
  end
end

class UnsupportedKeyziioVersionException < Exception
  # File is a newer version than this client can work with
  def to_s
    return 'File is a newer version than this client can work with'
  end
end

class KZHeader
  # The header is not a fixed length.  The format is as follows
  # Preamble : 128 byte string
  # Magic Number: 32 byte string preset as "d371004cba8d4fafaeb324f72a52d91b"
  # Version: 4 byte unsigned long
  # Length: Length of the header data(the rest of the header)
  # Header Data: Variable length string containing json encoded header data.  It currently just includes a 'key_id'
  #              key/value pair.
  attr_accessor :key_id, :mac, :magic_number

  def initialize
    @header = []
    @preamble = 'www.keyziio.com Encrypted File'
    @magic_number =  'd371004cba8d4fafaeb324f72a52d91b'
    @header_version = 1
    @fixed_header_section_length = 128 + 32 + 4 + 4 # pre
    @key_id = nil
    @mac = nil
  end

  def encode
    @header[0] = @preamble
    @header[1] = @magic_number.encode('US-ASCII')
    @header[2] = @header_version

    # content section
    header_dict = Hash.new
    header_dict['key_id'] = "#{@key_id}"
    header_dict['mac'] = "#{@mac}" if @mac
    @header[4] = header_dict.to_json #"{\"key_id\": \"#{@key_id}\"}"
    @header[3] = @header[4].bytesize

    return @header.pack("A128A32L<L<A#{@header[3]}")
  end

  def decode (packed_header)
    # decodes a packed header
    header_content_length = _decode_fixed_header_section(packed_header)
    header_content = packed_header.unpack("A128A32L<L<A#{header_content_length}")[4]
    _decode_header_content_section(header_content)
  end

  def _decode_fixed_header_section (packed_header)
    # Decodes the header, throws exceptions if it is invalid and returns the length of the data section
    if packed_header.length < @fixed_header_section_length
        raise KeyziioDecodeException
    end
    unpacked_header_wo_content = packed_header.unpack('A128A32L<L<')

    if unpacked_header_wo_content[0] != @preamble
      raise KeyziioDecodeException
    end

    if unpacked_header_wo_content[1] != @magic_number
      raise KeyziioDecodeException
    end

    if unpacked_header_wo_content[2] != @header_version
      raise UnsupportedKeyziioVersionException
    end

    # return content length
    return unpacked_header_wo_content[3]
  end

  def _decode_header_content_section (header_content)
    # decodes the header content from offset of header_content
    # header-data
    #@key_id = JSON.parse(header_content)['key_id']
    header_dict = JSON.parse(header_content)
    @key_id = header_dict['key_id']
    @mac = header_dict['mac']
  end

  def decode_header (io_object, is_file = false)
    # Decodes the header from a file.  If the file.equal? not a keyzio file we will throw a KeyzioDecodeException
    # Returns the length of the entire header (i.e. the offset for the real encrypted data
    if is_file
      fd = File.open(io_object, 'rb')
    else
      fd = StringIO.new(io_object)
    end
    fixed_header_section = fd.read(@fixed_header_section_length)
    header_content_length = _decode_fixed_header_section(fixed_header_section)
    header_content_section = fd.read(header_content_length)
    _decode_header_content_section(header_content_section)
    return @fixed_header_section_length + header_content_length
  end
end

#if __FILE__ == $0
#  # just for debugging...
#  h1 = KZHeader.new()
#  h1.key_id = 'mah key John Snow'
#  encoded_h1 = h1.encode()
#
#  h2 = KZHeader.new()
#  h2.decode(encoded_h1)
#
#  if(h1.key_id == h2.key_id)
#      print "they match\n"
#  else
#      print "no match\n"
#  end
#
##  h3 = KZHeader.new()
##  h3.decode_from_file('readme.enc')
##  print "Found key id:  #{h3.key_id}\n"
#end
