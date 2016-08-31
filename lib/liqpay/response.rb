require 'base64'
require 'liqpay/base_operation'

module Liqpay
  class Response < BaseOperation
    SUCCESS_STATUSES = %w(success wait_secure sandbox)

    ATTRIBUTES = %w(public_key order_id amount currency description type status transaction_id sender_phone)
    %w(public_key order_id description type action sandbox result_url server_url).each do |attr|
      attr_reader attr
    end

    # Amount of payment. MUST match the requested amount
    attr_reader :amount
    # Currency of payment. MUST match the requested currency
    attr_reader :currency
    # Status of payment. One of '
    #   failure 
    #   success
    #   wait_secure - success, but the card wasn't known to the system 
    #   sandbox
    attr_reader :status
    # LiqPAY's internal transaction ID
    attr_reader :transaction_id
    # Payer's phone
    attr_reader :sender_phone

    def initialize(params = {}, options = {})
      super(options)
      raise Liqpay::InvalidResponse unless params['signature'] == signature_from(params['data'])
      @raw_response = ActiveSupport::HashWithIndifferentAccess.new hash_from_data(params['data'])
      ATTRIBUTES.each do |attribute|
        instance_variable_set "@#{attribute}", @raw_response[attribute]
      end
      @action = @raw_response[:action] || 'pay'
      @sandbox = @raw_response[:sandbox] || 1
    end

    # extra fees taken by liqpay
    def commissions
      @raw_response.values_at(*%w(sender_commission receiver_commission agent_commission)).compact.reduce(&:+)
    end

    # Returns true, if the transaction was successful
    def success?
      SUCCESS_STATUSES.include? self.status
    end

    def signature_fields
      [amount, currency, public_key, order_id, type, description, status, transaction_id, sender_phone]
    end

    private

    def hash_from_data(data)
      JSON.parse(Base64.decode64(data))
    rescue JSON::ParserError
      {}
    end

    def signature_from(data)
      Base64.encode64(Digest::SHA1.digest(@private_key + data + @private_key)).strip
    end

    def decode!
      if signature != @request_signature
        raise Liqpay::InvalidResponse
      end
    end
  end
end
