from app import create_app
from db import db

app = create_app()

with app.app_context():
    # Execute raw SQL to modify the column length
    db.session.execute('ALTER TABLE users ALTER COLUMN password TYPE VARCHAR(256);')
    db.session.commit()
    print("Successfully updated password field length")
