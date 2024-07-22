# Imports
from config import db, app
from datetime import datetime
from models import User, Admin, Tenant, Property, Payment, MaintenanceRequest

def seed():
    # Clear existing data
    db.drop_all()
    db.create_all()
    
    # Create users
    users = [
        User(
            full_name="John Doe", 
            email="john@example.com", 
            phone_number="1234567890", 
            _password_hash="Password@123", 
            profile_picture="profile1.jpg", 
            role="tenant"
        ),
        User(
            full_name="Jane Doe", 
            email="jane@example.com", 
            phone_number="0987654321", 
            _password_hash="Password@123", 
            profile_picture="profile2.jpg", 
            role="tenant"
        ),
        User(
            full_name="Alice Smith", 
            email="alice@example.com", 
            phone_number="1122334455", 
            _password_hash="Password@123", 
            profile_picture="profile3.jpg", 
            role="tenant"
        ),
        User(
            full_name="Bob Brown", 
            email="bob@example.com", 
            phone_number="5566778899", 
            _password_hash="Password@123", 
            profile_picture="profile4.jpg", 
            role="tenant"
        )
    ]
    
    db.session.add_all(users)
    db.session.commit()
    
    # Create admins
    admins = [
        Admin(user_id=users[0].id),
        Admin(user_id=users[1].id)
    ]
    
    db.session.add_all(admins)
    db.session.commit()
    
    # Create properties
    properties = [
        Property(name="Property 1", location="1 Main St", image="property1.jpg", admin_id=admins[0].id),
        Property(name="Property 2", location="2 Main St", image="property2.jpg", admin_id=admins[1].id),
        Property(name="Property 3", location="3 Main St", image="property3.jpg", admin_id=admins[0].id),
        Property(name="Property 4", location="4 Main St", image="property4.jpg", admin_id=admins[1].id)
    ]
    
    db.session.add_all(properties)
    db.session.commit()
    
    # Create tenants
    tenants = [
        Tenant(house_number="A100", user_id=users[0].id, property_id=properties[0].id),
        Tenant(house_number="A102", user_id=users[1].id, property_id=properties[1].id),
        Tenant(house_number="A104", user_id=users[2].id, property_id=properties[2].id),
        Tenant(house_number="A106", user_id=users[3].id, property_id=properties[3].id)
    ]
    
    db.session.add_all(tenants)
    db.session.commit()
    
    # Create payments
    payments = [
        Payment(amount=1000, amount_due=500, user_id=users[0].id, tenant_id=tenants[0].id, admin_id=admins[0].id),
        Payment(amount=1200, amount_due=600, user_id=users[1].id, tenant_id=tenants[1].id, admin_id=admins[1].id),
        Payment(amount=1400, amount_due=700, user_id=users[2].id, tenant_id=tenants[2].id, admin_id=admins[0].id),
        Payment(amount=1600, amount_due=800, user_id=users[3].id, tenant_id=tenants[3].id, admin_id=admins[1].id)
    ]
    
    db.session.add_all(payments)
    db.session.commit()
    
    # Create maintenance requests
    maintenance_requests = [
        MaintenanceRequest(issue_type="Plumbing", description="Leaky faucet", tenant_id=tenants[0].id, admin_id=admins[0].id),
        MaintenanceRequest(issue_type="Electrical", description="Broken light switch", tenant_id=tenants[1].id, admin_id=admins[1].id),
        MaintenanceRequest(issue_type="HVAC", description="AC not cooling", tenant_id=tenants[2].id, admin_id=admins[0].id),
        MaintenanceRequest(issue_type="Pest Control", description="Rodent infestation", tenant_id=tenants[3].id, admin_id=admins[1].id)
    ]
    
    db.session.add_all(maintenance_requests)
    db.session.commit()

    print("Database seeded successfully!")

if __name__ == "__main__": 
    with app.app_context():
        seed()
