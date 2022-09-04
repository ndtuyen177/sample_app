class User < ApplicationRecord
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i

  before_save :downcase_email

  validates :email, presence: true, length: {minium: 20, maximum: 40},
    format: {with: VALID_EMAIL_REGEX},
    uniqueness: { case_sensitive: false }
  validates :name, presence: true, length: { maximum: 20 }
  validates :password, presence: true, length: { minimum: 6 }, if: :password
  has_secure_password

  attr_accessor :remember_token
  class << self
    def digest string
      cost = if ActiveModel::SecurePassword.min_cost
               BCrypt::Engine::MIN_COST
             else
               BCrypt::Engine.cost
             end
      BCrypt::Password.create string, cost: cost
    end

    def new_token
      SecureRandom.urlsafe_base64
    end

  end
  def remember
    self.remember_token = User.new_token
    update remember_digest: User.digest(remember_token)
  end

  def authenticated? remember_token
    return false unless remember_token

    BCrypt::Password.new(remember_digest).is_password? remember_token
  end

  def forget
    update_attribute :remember_digest, nil
  end

  private

  def downcase_email
    self.email.downcase!
  end

end
