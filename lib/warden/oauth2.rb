require 'warden'
require 'warden/oauth2/version'

module Warden
  module OAuth2
    class Configuration
      attr_accessor :client_credentials_model,
                    :resource_owner_password_credentials_model,
                    :token_model,
                    :refresh_token_model,
                    :facebook_access_token_model

      def initialize
        self.client_credentials_model = ClientCredentialsApplication if defined?(ClientCredentialsApplication)
        self.resource_owner_password_credentials_model = ResourceOwnerPasswordCredentialsApplication if defined?(ResourceOwnerPasswordCredentialsApplication)
        self.refresh_token_model = RefreshTokenApplication if defined?(RefreshTokenApplication)
        self.token_model = AccessToken if defined?(AccessToken)
        self.facebook_access_token_model = FacebookAccessToken if defined?(FacebookAccessToken)
      end
    end

    def self.config
      @@config ||= Configuration.new
    end

    def self.configure
      yield config
    end

    autoload :FailureApp, 'warden/oauth2/failure_app'
    module Strategies
      autoload :Base,   'warden/oauth2/strategies/base'
      autoload :Public, 'warden/oauth2/strategies/public'
      autoload :Token,  'warden/oauth2/strategies/token'
      autoload :Client, 'warden/oauth2/strategies/client'
      autoload :ClientCredentials, 'warden/oauth2/strategies/client_credentials'
      autoload :ResourceOwnerPasswordCredentials, 'warden/oauth2/strategies/resource_owner_password_credentials'
      autoload :IssuingAccessToken, 'warden/oauth2/strategies/issuing_access_token'
      autoload :AccessingProtectedResource, 'warden/oauth2/strategies/accessing_protected_resource'
      autoload :Bearer, 'warden/oauth2/strategies/bearer'
      autoload :RefreshToken, 'warden/oauth2/strategies/refresh_token'
      autoload :FacebookAccessToken, 'warden/oauth2/strategies/facebook_access_token'
    end
  end
end
