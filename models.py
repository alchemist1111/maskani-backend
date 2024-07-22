# Imports
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates
# from sqlalchemy import ForeignKeyConstraint
from config import db, bcrypt
from datetime import datetime
import re

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    phone_number = db.Column(db.String, nullable=False)
    _password_hash = db.Column(db.String, nullable=False)
    profile_picture = db.Column(db.String(200))
    role = db.Column(db.String(10), nullable=False)  # 'tenant' or 'admin'
    
    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password is not a readable attribute')

    @password_hash.setter
    def password_hash(self,password):
        password_hash = bcrypt.generate_password_hash(password.encode("utf-8"))
        self._password_hash = password_hash.decode("utf-8")

    def authenticate(self,password):
        return bcrypt.check_password_hash(self._password_hash,password.encode("utf-8"))
    

    def is_active(self):
        return True
    
    # association proxies
    maintenance_requests = association_proxy('tenant', 'maintenance_requests')
    properties = association_proxy('admin', 'properties')
    
    # serialize rules
    serialize_rules = ('-tenant.user', '-admin.user', '-payments.user',)

    # relationships
    tenant = db.relationship('Tenant', back_populates='user', uselist=False)
    admin = db.relationship('Admin', back_populates='user', uselist=False)
    payments = db.relationship('Payment', back_populates='user', foreign_keys='Payment.user_id')
    
    # validations
    @validates('full_name')
    def validate_user_full_name(self, key, full_name):
        if not full_name:
            raise ValueError("Full name must be provided")
        elif User.query.filter(User.full_name == full_name).first():
            raise ValueError("Full name must be unique")
        return full_name 
    
    @validates('email')
    def validate_user_email(self, key, email):
        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
            raise ValueError("Invalid email address")
        elif User.query.filter(User.email == email).first():
            raise ValueError("Email must be unique")
        return email 
    
    # @validates('phone_number')
    # def validate_user_phone_number(self, key, phone_number):
    #     digits = ''.join(filter(str.isdigit, phone_number))
    #     if len(digits) != 10:
    #         raise ValueError("Phone number must be 10 digits")
    #     return phone_number
    
    @validates('password')
    def validate_user_password(self, key, password):
        if not password:
            raise ValueError("Password cannot be empty")
        password_pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(password_pattern, password):
            raise ValueError("Password must be at least 8 characters long, contain at least one uppercase letter, one number, and one special character")
        return password

    def __repr__(self):
        return f'<User id={self.id}, full_name={self.full_name}, email={self.email}, phone_number={self.phone_number}, profile_picture={self.profile_picture}, role={self.role}>'


class Tenant(db.Model, SerializerMixin):
    __tablename__ = 'tenants'

    id = db.Column(db.Integer, primary_key=True)
    house_number = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user = db.relationship('User', back_populates='tenants')
    property_id = db.Column(db.Integer, db.ForeignKey("properties.id"), nullable=False)


    # validations
    @validates('house_number')
    def validate_tenant_house_number(self, key, house_number):
        if not house_number:
            raise ValueError("House number must be provided")
        return house_number
        
    
    
     # serialize rules
    serialize_rules = ('-user.tenant', '-payments.tenant', '-maintenance_requests.tenant', '-property.tenants',)


    # relationships
    user = db.relationship('User', back_populates='tenant')
    payments = db.relationship('Payment', back_populates='tenant', foreign_keys='Payment.tenant_id')
    maintenance_requests = db.relationship('MaintenanceRequest', back_populates='tenant', cascade ='all, delete-orphan')
    property = db.relationship('Property', back_populates='tenants', foreign_keys=[property_id])


    
    def __repr__(self):
        return f'<Tenant id={self.id}, house_number={self.house_number}, user_id={self.user_id}>'

    
class Admin(db.Model, SerializerMixin):
    __tablename__ = 'admins'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    
    # serialize rules
    serialize_rules = ('-user.admin', '-payments.admin', '-properties.admin', '-maintenance_requests.admin',)

    # relationships
    user = db.relationship('User', back_populates='admin')
    payments = db.relationship('Payment', back_populates='admin', foreign_keys='Payment.admin_id')
    properties = db.relationship('Property', back_populates = 'admin', cascade ='all, delete-orphan')
    maintenance_requests = db.relationship('MaintenanceRequest', back_populates='admin', cascade ='all, delete-orphan')



    def __repr__(self) -> str:
        return f'<Admin id={self.id}, user_id={self.user_id}>'    

class Payment(db.Model, SerializerMixin):
    __tablename__ = 'payments'
    
    id = db.Column(db.Integer, primary_key=True)
    date_payed = db.Column(db.DateTime, default=datetime.utcnow)
    amount = db.Column(db.Float, nullable=False)
    amount_due = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'))

    # validations
    @validates('amount')
    def validate_payment_amount(self, key, amount):
        if not isinstance(amount, (int, float)) or amount < 0:
            raise ValueError(f"{key} must be a positive number")
        return amount
    
    @validates('amount_due')
    def validate_payment_amount_due(self, key, amount_due):
        if not isinstance(amount_due, (int, float)) or amount_due < 0:
            raise ValueError(f"{key} must be a positive number")
        return amount_due
    
      # serialize rules
    serialize_rules = ('-tenant.payments', '-user.payments', '-admin.payments',)

    # relationships
    tenant = db.relationship('Tenant', back_populates='payments', foreign_keys=[tenant_id])
    user = db.relationship('User', back_populates='payments', foreign_keys=[user_id])
    admin = db.relationship('Admin', back_populates='payments', foreign_keys=[admin_id])
        

    def __repr__(self):
        return f'<Payment id={self.id}, date_payed={self.date_payed}, amount={self.amount}, amount_due={self.amount_due}>'


class Property(db.Model, SerializerMixin):
    __tablename__ = 'properties'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(200))
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)
    



    # validations
    @validates('name')
    def validate_property_name(self, key, name):
        if not name:
            raise ValueError("Name must be provided")
        elif Property.query.filter(Property.name == name).first():
            raise ValueError("Name must be unique")
        return name
    
    @validates('location')
    def validate_property_location(self, key, location):
        if not location:
            raise ValueError("Location must be provided")
        return location
    
    # association proxy
    maintenance_requests = association_proxy('tenants', 'maintenance_requests')
    

    # serialize rules
    serialize_rules = ('-admin.properties', '-tenants.property',)


    # relationships
    admin = db.relationship('Admin', back_populates='properties')
    tenants = db.relationship('Tenant', back_populates='property', cascade ='all, delete-orphan')
    

    def __repr__(self):
        return f'<Property id={self.id}, name={self.name}, location={self.location}, owner={self.owner}>'

class MaintenanceRequest(db.Model, SerializerMixin):
    __tablename__ = 'maintenance_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    issue_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)
    
    # serialize rules
    serialize_rules = ('-tenant.maintenance_requests', '-admin.maintenance_requests',)

    # validations
    @validates('issue_type')
    def validate_maintenance_request_issue_type(self, key, issue_type):
        if not issue_type:
            raise ValueError("Issue type must be provided")
        return issue_type
    
    @validates('description')
    def validate_maintenance_request_description(self, key, description):
        if not description:
            raise ValueError("Description must be provided")
        return description
    
    # relationships
    tenant = db.relationship('Tenant', back_populates='maintenance_requests')
    admin = db.relationship('Admin', back_populates='maintenance_requests')


    def __repr__(self):
        return f'<Maintenance id={self.id}, issue_type={self.issue_type}, description={self.description}>'
