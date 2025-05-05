import os
from app import create_app

app = create_app()

# Ensure the uploads directory exists
uploads_dir = os.path.join(app.root_path, '../uploads')
os.makedirs(uploads_dir, exist_ok=True)

# Ensure the database and tables exist
with app.app_context():
    db_path = os.path.join(app.root_path, '../instance/site.db')
    if not os.path.exists(db_path):
        from app import db
        db.create_all()
        print("Database initialized!")

if __name__ == '__main__':
    app.run(
        debug=True,
        ssl_context=('certs/cert.pem', 'certs/key.pem'),
        host='0.0.0.0',
        port=443
    )
