#require_relative 'version.rb'
require 'logger'
require 'json'
require 'rest-client'

class AuthFailure < Exception
  # Authentication attempt failed
end

class ServerFailure < Exception
  # Connected to the server, but failed for some non-auth reason
end

class ConnectionFailure < Exception
  # Not connected to the server at all
end

class UnverifiedUser < Exception
  # User authenticated successfully, however it seems their verification link has yet to be processed
end

class KZRestClient < Object
    # Our Rest Client
    attr_accessor :server_url, :server_port

    def initialize (server_url='keyziio.herokuapp.com', server_port=80, use_ssl=false)
      @server_url = server_url
      @server_port = server_port
      @use_ssl = use_ssl
      @auth_data = nil
      @session = nil

      @user_key_path = 'api/v1/data_keys/'
      @sessions_path = 'sessions.json'
      @users_path = 'users.json'
      @common_header = Hash.new
      @common_header['content_type'] = 'json'
      @common_header['accept'] = 'json'
      @common_header['user_agent'] = 'json'
    end

    def rest_exception_handler (code)
      if [401, 422].include? code
        raise AuthFailure
      elsif code == 404
        raise UnverifiedUser
      elsif [500, 501].include? code
        raise ServerFailure
      elsif code == 503
        raise ConnectionFailure
      end
    end

    def _url (path)
      return '%s://%s:%s/%s' % [@use_ssl ? 'https' : 'http', @server_url, @server_port, path]
    end

    def common_headers
      {:content_type => :json,
       :accept => :json,
       :user_agent => 'Keyziio Ruby Client'}
    end

    def get_key (key_id, user_id)
      begin
        response = RestClient.get _url(@user_key_path + key_id.to_s), {:params => {'user_id' => user_id},
                                                                       :content_type => :json,
                                                                       :accept => :json,
                                                                       :user_agent => 'Keyziio Ruby Client'}
      rescue Errno::ECONNREFUSED
        raise ConnectionFailure
      rescue StandardError => e
        e.response
        raise
      end
      return response
    end

    def get_new_key (key_id, user_id)
      begin
        response = RestClient.post _url(@user_key_path), {'user_id' => user_id, 'name' => key_id}.to_json,
                                                         :content_type => :json,
                                                         :accept => :json,
                                                         :user_agent => 'Keyziio Ruby Client'
      rescue Errno::ECONNREFUSED
        raise ConnectionFailure
      rescue => e
        e.response
        raise
      end

      return response
    end

    def put (path, data=nil)
      begin
        response = RestClient.put _url(path), common_headers
      rescue Errno::ECONNREFUSED
        raise ConnectionFailure
      rescue => e
        e.response
        raise
      end
      return response
    end
    
    def get (path)
      begin
        response = RestClient.get _url(path), common_headers
      rescue Errno::ECONNREFUSED
        raise ConnectionFailure
      rescue => e
        e.response
        raise
      end
      return response
    end


    def post (path, data=nil)
      begin
        response = RestClient.post _url(path), common_headers
      rescue Errno::ECONNREFUSED
        raise ConnectionFailure
      rescue => e
        e.response
        raise
      end
      return response
    end
    
    def delete (path)
      begin
        response = RestClient.delete _url(path), common_headers
      rescue Errno::ECONNREFUSED
        raise ConnectionFailure
      rescue => e
        e.response
        raise
      end
      return response
    end
end

if __FILE__ == $0
  rc = KZRestClient.new()
  resp = rc.get_key('my_test_key_1', 'c87f689e-85d5-46b3-81ba-ce9666371d45')
end
