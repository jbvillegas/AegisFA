from app import create_app, database

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        database.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)