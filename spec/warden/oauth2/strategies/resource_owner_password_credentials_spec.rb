require 'spec_helper'

describe Warden::OAuth2::Strategies::ResourceOwnerPasswordCredentials do
  let(:strategy) { described_class }
  let(:client_model) { double(:ClientApplication) }
  subject { strategy.new('rack.input' => {}) }

  before do
    Warden::OAuth2.config.resource_owner_password_credentials_model = client_model
  end

  describe '#valid?' do
    it 'returns false if the grant type is not specified' do
      allow(subject).to receive(:params).and_return({})
      expect(subject).to_not be_valid
    end

    it 'returns true if the grant type is password' do
      allow(subject).to receive(:params).and_return('grant_type' => 'password')
      expect(subject).to be_valid
    end

    it 'returns false if the grant type is not password' do
      allow(subject).to receive(:params).and_return('grant_type' => 'whatever')
      expect(subject).to_not be_valid
    end
  end

  describe '#authenticate!' do
    context 'when the client is around but not valid' do
      context 'when the client is confirmed' do
        it 'should fail with incorrect username or password message' do
          client_instance = double(:client_instance, valid?: false, confirmed?: true)
          allow(client_model).to receive_messages(locate: client_instance)
          allow(subject).to receive(:params).and_return('client_id' => 'awesome', 'username' => 'someuser', 'password' => 'incorrect')
          subject._run!
          expect(subject.error_status).to eq(401)
          expect(subject.message).to eq('invalid_client')
          expect(subject.error_description).to eq('Incorrect username or password')
        end
      end

      context 'when the client is not confirmed' do
        it 'should fail with a please confirm your account message' do
          client_instance = double(:client_instance, valid?: false, confirmed?: false)
          allow(client_model).to receive_messages(locate: client_instance)
          allow(subject).to receive(:params).and_return('client_id' => 'awesome', 'username' => 'someuser', 'password' => 'incorrect')
          subject._run!
          expect(subject.error_status).to eq(401)
          expect(subject.message).to eq('invalid_client')
          expect(subject.error_description).to eq('Please confirm your account prior to use our service')
        end
      end
    end

    it 'should fail if username and password are not provided' do
      allow(client_model).to receive_messages(locate: double)
      allow(subject).to receive(:params).and_return('client_id' => 'awesome')
      subject._run!
      expect(subject.error_status).to eq(400)
      expect(subject.message).to eq('invalid_request')
      expect(subject.error_description).to_not be_empty
    end

    it 'should pass username and password to validation check' do
      client_instance = double(:client_instance)
      allow(client_model).to receive_messages(locate: client_instance)
      allow(subject).to receive(:params).and_return('client_id' => 'awesome', 'username' => 'username', 'password' => 'password')

      expect(client_instance).to receive(:valid?).with(username: 'username', password: 'password').and_return(true)

      subject._run!
    end

    it 'should succeed if client is around and valid' do
      client_instance = double(:client_instance, valid?: true)
      allow(client_model).to receive_messages(locate: client_instance)
      allow(subject).to receive(:params).and_return('client_id' => 'awesome', 'username' => 'username', 'password' => 'correct')
      subject._run!
      expect(subject.user).to eq(client_instance)
      expect(subject.result).to eq(:success)
    end
  end
end
