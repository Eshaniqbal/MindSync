from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS
from pymongo import MongoClient

app = Flask(__name__)
CORS(app)  # Add this line to enable CORS
app.config['JWT_SECRET_KEY'] = 'eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkphdmFJblVzZSIsImV4cCI6MTcxODM3ODA2OSwiaWF0IjoxNzE4Mzc4MDY5fQ.-4HMZUyz6AuWPTiB3lnczGPNNMbtvCu-AYVI-DgqvhE'
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
client = MongoClient('mongodb://localhost:27017/')
db = client['mental_health']
users_collection = db['users']
blacklist = set()  # Set to store JWT tokens to blacklist on logout

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if users_collection.find_one({'username': username}):
        return jsonify({"msg": "Username already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    users_collection.insert_one({
        'username': username,
        'password': hashed_password
    })

    return jsonify({"msg": "Signup successful"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = users_collection.find_one({'username': username})
    if user and bcrypt.check_password_hash(user['password'], password):
        access_token = create_access_token(identity={'username': username})
        return jsonify(access_token=access_token), 200

    return jsonify({"msg": "Bad username or password"}), 401

@app.route('/resources', methods=['GET'])
def get_resources():
    token = request.headers.get('Authorization').split()[1]
    if not token:
        return jsonify({"msg": "Missing token"}), 401
    # Here you would verify the token and get the resources
    # Dummy data for now
    resources = [
        {"_id": "1", "category": "Anxiety", "title": "Understanding Anxiety", "description": "Learn about symptoms and coping strategies for anxiety."},
        {"_id": "2", "category": "Depression", "title": "Dealing with Depression", "description": "Resources to understand and manage depression."},
        {"_id": "3", "category": "Stress Management", "title": "Effective Stress Management Techniques", "description": "Tips and techniques to manage stress effectively."},
        {"_id": "4", "category": "Self-care", "title": "Importance of Self-care", "description": "Learn why self-care is important for mental well-being."},
        {"_id": "5", "category": "Mindfulness", "title": "Introduction to Mindfulness", "description": "Techniques to cultivate mindfulness in daily life."},
        {"_id": "6", "category": "Coping Skills", "title": "Developing Coping Skills", "description": "Strategies to develop effective coping skills."},
    ]
    return jsonify(resources), 200

@app.route('/account', methods=['GET'])
@jwt_required()
def account():
    current_user = get_jwt_identity()
    return jsonify({"username": current_user}), 200

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    # There is no get_raw_jwt(), using the identity instead
    current_user = get_jwt_identity()
    return jsonify({"msg": f"Successfully logged out user {current_user}"}), 200

if __name__ == '__main__':
    app.run(debug=True)
