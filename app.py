from app import create_app, db
from flask import Flask
import os

app = create_app()

# Create the database if it doesn't exist
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
