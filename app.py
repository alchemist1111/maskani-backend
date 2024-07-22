from flask import Flask, request, make_response, jsonify
from flask_restful import Api, Resource
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, jwt_required
)
import os
from config import db, app
from models import User, Tenant, Admin, Payment, Property, MaintenanceRequest 

# Configurations
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "super-secret-key")
app.config['JWT_TOKEN_LOCATION'] = ['headers']
jwt = JWTManager(app)
api = Api(app)



@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()

class Home(Resource):
    def get(self):
        return {"message": "Welcome to Maskani"}

api.add_resource(Home, '/')

# User Registration
class UserRegistration(Resource):
    def post(self):
        data = request.get_json()
        full_name = data.get('full_name')
        email = data.get('email')
        phone_number = data.get('phone_number')
        password = data.get('password')
        profile_picture = data.get('profile_picture')
        role = data.get('role')

        user = User.query.filter_by(email=email).first()

        if not user:
            try:
                user = User(
                    full_name=full_name,
                    email=email,
                    phone_number=phone_number,
                    profile_picture=profile_picture,
                    role=role
                )
                user.password_hash = password

                db.session.add(user)
                db.session.commit()

                access_token = create_access_token(identity=user)
                return make_response({"user":user.to_dict(),'access_token': access_token},201)
            
            except Exception as e:

                return {'error': e.args}, 422
        else: 
             
            return make_response({'error':"Email already registered, kindly log in"},401)

api.add_resource(UserRegistration, '/register', endpoint='/register')

# User Login
class UserLogin(Resource):
   def post(self):
        data = request.get_json()
        user = User.query.filter_by(email=data.get('email')).first()
        if user:
            if user.authenticate(data.get('password')):
                access_token = create_access_token(identity=user)
                response = make_response({"user":user.to_dict(),'access_token': access_token},201)
                return response
            else:
                 return make_response({'error':"Incorrect password"},401)
        else:
             return make_response({'error':"Unauthorized"},401)
        
api.add_resource(UserLogin,'/login',endpoint="login")

class CheckSession(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        return make_response(jsonify(user.to_dict()), 200)

api.add_resource(CheckSession, '/check_session')

# User CRUD operations
class Users(Resource):
    def get(self):
        users = User.query.all()
        users_list = [{
            'id': user.id,
            'full_name': user.full_name,
            'email': user.email,
            'phone_number': user.phone_number,
            'profile_picture': user.profile_picture,
            'role': user.role
        } for user in users]
        return make_response(jsonify(users_list), 200)

    def get(self, user_id):
        user = User.query.get_or_404(user_id)
        user_dict = {
            'id': user.id,
            'full_name': user.full_name,
            'email': user.email,
            'phone_number': user.phone_number,
            'profile_picture': user.profile_picture,
            'role': user.role
        }
        return make_response(jsonify(user_dict), 200)

    def put(self, user_id):
        data = request.get_json()
        user = User.query.get_or_404(user_id)
        user.full_name = data.get('full_name')
        user.email = data.get('email')
        user.phone_number = data.get('phone_number')
        user.profile_picture = data.get('profile_picture')
        user.role = data.get('role')
        db.session.commit()
        user_dict = {
            'id': user.id,
            'full_name': user.full_name,
            'email': user.email,
            'phone_number': user.phone_number,
            'profile_picture': user.profile_picture,
            'role': user.role
        }
        return make_response(jsonify(user_dict), 200)

    def delete(self, user_id):
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return make_response(jsonify({'message': 'User deleted'}), 200)

api.add_resource(Users, '/users', '/users/<int:user_id>')

# Property information
class Properties(Resource):
    def get(self):
        properties = Property.query.all()
        properties_list = [{
            'id': property.id,
            'name': property.name,
            'location': property.location,
            'image': property.image,
            'admin_id': property.admin_id
        } for property in properties]
        return make_response(jsonify(properties_list), 200)

    def get(self, property_id):
        property = Property.query.get_or_404(property_id)
        property_dict = {
            'id': property.id,
            'name': property.name,
            'location': property.location,
            'image': property.image,
            'admin_id': property.admin_id
        }
        return make_response(jsonify(property_dict), 200)

    def post(self):
        data = request.get_json()
        new_property = Property(
            name=data.get('name'), 
            location=data.get('location'), 
            image=data.get('image'),
            admin_id=data.get('admin_id')
        )
        db.session.add(new_property)
        db.session.commit()
        property_dict = {
            'id': new_property.id,
            'name': new_property.name,
            'location': new_property.location,
            'image': new_property.image,
            'admin_id': new_property.admin_id
        }
        return make_response(jsonify(property_dict), 201, {"content-type": "application/json"})

    def put(self, property_id):
        data = request.get_json()
        property = Property.query.get_or_404(property_id)
        property.name = data.get('name')
        property.location = data.get('location')
        property.image = data.get('image')
        property.admin_id = data.get('admin_id')
        db.session.commit()
        property_dict = {
            'id': property.id,
            'name': property.name,
            'location': property.location,
            'image': property.image,
            'admin_id': property.admin_id
        }
        return make_response(jsonify(property_dict), 200)

    def delete(self, property_id):
        property = Property.query.get_or_404(property_id)
        db.session.delete(property)
        db.session.commit()
        return make_response(jsonify({'message': 'Property deleted'}), 200)

api.add_resource(Properties, '/properties', '/properties/<int:property_id>')

# Payment information
class Payments(Resource):
    def get(self, payment_id=None):
        if payment_id is None:
            # Return list of all payments
            payments = Payment.query.all()
            payments_list = [{
                'id': payment.id,
                'date_payed': payment.date_payed,
                'amount': payment.amount,
                'amount_due': payment.amount_due,
                'user_id': payment.user_id,
                'tenant_id': payment.tenant_id,
                'admin_id': payment.admin_id 
            } for payment in payments]
            return make_response(jsonify(payments_list), 200)
        else:
            # Return a specific payment
            payment = Payment.query.get_or_404(payment_id)
            payment_dict = {
                'id': payment.id,
                'date_payed': payment.date_payed,
                'amount': payment.amount,
                'amount_due': payment.amount_due,
                'user_id': payment.user_id,
                'tenant_id': payment.tenant_id,
                'admin_id': payment.admin_id,
            }
            return make_response(jsonify(payment_dict), 200)

    def post(self):
        data = request.get_json()
        new_payment = Payment(
            date_payed=data.get('date_payed'),
            amount=data.get('amount'),
            amount_due=data.get('amount_due'),
            user_id=data.get('user_id'),
            tenant_id=data.get('tenant_id'),
            admin_id=data.get('admin_id')
        )
        db.session.add(new_payment)
        db.session.commit()
        payment_dict = {
            'id': new_payment.id,
            'date_payed': new_payment.date_payed,
            'amount': new_payment.amount,
            'amount_due': new_payment.amount_due,
            'user_id': new_payment.user_id,
            'tenant_id': new_payment.tenant_id,
            'admin_id': new_payment.admin_id
        }
        return make_response(jsonify(payment_dict), 201, {"content-type": "application/json"})

    def put(self, payment_id):
        data = request.get_json()
        payment = Payment.query.get_or_404(payment_id)
        payment.date_payed = data.get('date_payed')
        payment.amount = data.get('amount')
        payment.amount_due = data.get('amount_due')
        payment.user_id = data.get('user_id')
        payment.tenant_id = data.get('tenant_id')
        payment.admin_id = data.get('admin_id')
        db.session.commit()
        payment_dict = {
            'id': payment.id,
            'date_payed': payment.date_payed,
            'amount': payment.amount,
            'amount_due': payment.amount_due,
            'user_id': payment.user_id,
            'tenant_id': payment.tenant_id,
            'admin_id': payment.admin_id,
        }
        return make_response(jsonify(payment_dict), 200)

    def delete(self, payment_id):
        payment = Payment.query.get_or_404(payment_id)
        db.session.delete(payment)
        db.session.commit()
        return make_response(jsonify({'message': 'Payment deleted'}), 200)

api.add_resource(Payments, '/payments', '/payments/<int:payment_id>')

# MaintenanceRequest information
class MaintenanceRequests(Resource):
    def get(self, maintenance_request_id=None):
        if maintenance_request_id is None:
            maintenance_requests = MaintenanceRequest.query.all()
            maintenance_requests_list = [{
                'id': mr.id,
                'issue_type': mr.issue_type,
                'description': mr.description,
                'date_created': mr.date_created,
                'tenant_id': mr.tenant_id,
                'admin_id': mr.admin_id 
            } for mr in maintenance_requests]
            return make_response(jsonify(maintenance_requests_list), 200)
        else:
            maintenance_request = MaintenanceRequest.query.get_or_404(maintenance_request_id)
            maintenance_request_dict = {
                'id': maintenance_request.id,
                'issue_type': maintenance_request.issue_type,
                'description': maintenance_request.description,
                'date_created': maintenance_request.date_created,
                'tenant_id': maintenance_request.tenant_id,
                'admin_id': maintenance_request.admin_id
            }
            return make_response(jsonify(maintenance_request_dict), 200)

    def post(self):
        data = request.get_json()
        new_maintenance_request = MaintenanceRequest(
            issue_type=data.get('issue_type'),
            description=data.get('description'),
            date_created=data.get('date_created'),
            tenant_id=data.get('tenant_id'),
            admin_id=data.get('admin_id')
        )
        db.session.add(new_maintenance_request)
        db.session.commit()
        maintenance_request_dict = {
            'id': new_maintenance_request.id,
            'issue_type': new_maintenance_request.issue_type,
            'description': new_maintenance_request.description,
            'date_created': new_maintenance_request.date_created,
            'tenant_id': new_maintenance_request.tenant_id,
            'admin_id': new_maintenance_request.admin_id
        }
        return make_response(jsonify(maintenance_request_dict), 201, {"content-type": "application/json"})

    def put(self, maintenance_request_id):
        data = request.get_json()
        maintenance_request = MaintenanceRequest.query.get_or_404(maintenance_request_id)
        maintenance_request.issue_type = data.get('issue_type')
        maintenance_request.description = data.get('description')
        maintenance_request.date_created = data.get('date_created')
        maintenance_request.tenant_id = data.get('tenant_id')
        maintenance_request.admin_id = data.get('admin_id')
        db.session.commit()
        maintenance_request_dict = {
            'id': maintenance_request.id,
            'issue_type': maintenance_request.issue_type,
            'description': maintenance_request.description,
            'date_created': maintenance_request.date_created,
            'tenant_id': maintenance_request.tenant_id,
            'admin_id': maintenance_request.admin_id
        }
        return make_response(jsonify(maintenance_request_dict), 200)

    def delete(self, maintenance_request_id):
        maintenance_request = MaintenanceRequest.query.get_or_404(maintenance_request_id)
        db.session.delete(maintenance_request)
        db.session.commit()
        return make_response(jsonify({'message': 'Maintenance request deleted'}), 200)

api.add_resource(MaintenanceRequests, '/maintenance_requests', '/maintenance_requests/<int:maintenance_request_id>')
# Tenant information
class Tenants(Resource):
    def get(self):
        tenants = Tenant.query.all()
        tenants_list = [{
            'id': tenant.id,
            'house_number': tenant.house_number,
            'user_id': tenant.user_id,
            'property_id': tenant.property_id
        } for tenant in tenants]
        return make_response(jsonify(tenants_list), 200)

    def get(self, tenant_id):
        tenant = Tenant.query.get_or_404(tenant_id)
        tenant_dict = {
            'id': tenant.id,
            'house_number': tenant.house_number,
            'user_id': tenant.user_id,
            'property_id': tenant.property_id
        }
        return make_response(jsonify(tenant_dict), 200)

    def put(self, tenant_id):
        data = request.get_json()
        tenant = Tenant.query.get_or_404(tenant_id)
        tenant.house_number = data.get('house_number')
        tenant.user_id = data.get('user_id')
        tenant.property_id = data.get('property_id')
        db.session.commit()
        tenant_dict = {
            'id': tenant.id,
            'house_number': tenant.house_number,
            'user_id': tenant.user_id,
            'property_id': tenant.property_id
        }
        return make_response(jsonify(tenant_dict), 200)

    def delete(self, tenant_id):
        tenant = Tenant.query.get_or_404(tenant_id)
        db.session.delete(tenant)
        db.session.commit()
        return make_response(jsonify({'message': 'Tenant deleted'}), 200)

api.add_resource(Tenants, '/tenants', '/tenants/<int:tenant_id>')

# Admin information
class Admins(Resource):
    def get(self):
        admins = Admin.query.all()
        admins_list = [{
            'id': admin.id,
            'user_id': admin.user_id
        } for admin in admins]
        return make_response(jsonify(admins_list), 200)

    def get(self, admin_id):
        admin = Admin.query.get_or_404(admin_id)
        admin_dict = {
            'id': admin.id,
            'user_id': admin.user_id
        }
        return make_response(jsonify(admin_dict), 200)

    def put(self, admin_id):
        data = request.get_json()
        admin = Admin.query.get_or_404(admin_id)
        admin.user_id = data.get('user_id')
        db.session.commit()
        admin_dict = {
            'id': admin.id,
            'user_id': admin.user_id
        }
        return make_response(jsonify(admin_dict), 200)

    def delete(self, admin_id):
        admin = Admin.query.get_or_404(admin_id)
        db.session.delete(admin)
        db.session.commit()
        return make_response(jsonify({'message': 'Admin deleted'}), 200)

api.add_resource(Admins, '/admins', '/admins/<int:admin_id>')

if __name__ == '__main__':
    app.run(port=5600, debug=True)
