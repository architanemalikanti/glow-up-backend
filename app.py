# app.py
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from datetime import datetime, timedelta
import re
import json
import requests  # ← MISSING - for API calls
from openai import OpenAI    # ← MISSING - for OpenAI API calls
import os        # ← MISSING - for environment variables
from dotenv import load_dotenv  # ← MISSING - to load .env file

app = Flask(__name__)

load_dotenv()

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# Add this flag variable near the top after creating your Flask app
first_request_done = False

@app.before_request
def before_first_request_func():
    global first_request_done
    if not first_request_done:
        # Put ALL your initialization code here
        def create_tables():
            db.create_all()
        # Whatever you had in your @app.before_first_request function
        print("Running first-time initialization...")
        first_request_done = True



# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///glowgirl.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-change-this-too'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)  # Token lasts 30 days

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)  # Allow iOS app to connect

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'created_at': self.created_at.isoformat()
        }

# Helper functions
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Routes

#route #1: register
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # Validate input
        if not data or not all(k in data for k in ('email', 'username', 'password')):
            return jsonify({'error': 'Missing required fields'}), 400
        
        email = data['email'].strip().lower()
        username = data['username'].strip()
        password = data['password']
        
        # Validation
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already taken'}), 400
        
        # Create new user
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            email=email,
            username=username,
            password_hash=password_hash
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Create JWT token
        # Create JWT token with string identity
        token = create_access_token(identity=str(new_user.id))
        
        return jsonify({
            'message': 'Registration successful',
            'token': token,
            'user': new_user.to_dict()
        }), 201
        
    except Exception as e:
        return jsonify({'error': 'Registration failed'}), 500

#route #2: login
@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        # Validate input
        if not data or not all(k in data for k in ('email', 'password')):
            return jsonify({'error': 'Missing email or password'}), 400
        
        email = data['email'].strip().lower()
        password = data['password']
        
        # Find user
        user = User.query.filter_by(email=email).first()
        
        # Check password
        if user and bcrypt.check_password_hash(user.password_hash, password):
            # Create JWT token
            token = create_access_token(identity=user.id)
            
            return jsonify({
                'message': 'Login successful',
                'token': token,
                'user': user.to_dict()
            }), 200
        else:
            return jsonify({'error': 'Invalid email or password'}), 401
            
    except Exception as e:
        return jsonify({'error': 'Login failed'}), 500


#route #3: get current user info
@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    try:
        # Get user ID from JWT token
        current_user_id = int(get_jwt_identity())  # ← ADD int() here
        user = User.query.get(current_user_id)
        
        if user:
            return jsonify({
                'user': user.to_dict()
            }), 200
        else:
            return jsonify({'error': 'User not found'}), 404
            
    except Exception as e:
        return jsonify({'error': 'Failed to get user info'}), 500

# Optional: Logout route (for token blacklisting - advanced)
@app.route('/api/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    # In a simple implementation, logout is handled client-side by deleting the token
    # For advanced security, you'd implement token blacklisting here
    return jsonify({'message': 'Logout successful'}), 200



#START HERE
@app.route('/api/glow-up-advice', methods=['POST'])
def get_glow_up_advice():
    vent_text = request.json.get('vent_text')
    
    # Step 1: Analyze emotional context
    emotional_analysis = analyze_emotional_context(vent_text)
    print(f"Emotional analysis: {emotional_analysis}")
    
    # Step 2: Get product strategy from GPT
    product_strategy = get_product_strategy_from_gpt(emotional_analysis, vent_text)
    print(f"Product strategy: {product_strategy}")  # ← ADD THIS
    print(f"Keys in product_strategy: {list(product_strategy.keys())}")  # ← ADD THIS
    
    # Step 3: Search for real products using multiple APIs
    raw_products = search_real_products(product_strategy)
    
    # Step 4: Let GPT curate final recommendations
    final_recommendations = curate_with_gpt(raw_products, emotional_analysis, vent_text)
    
    return jsonify(final_recommendations)

def analyze_emotional_context(vent_text):
    prompt = f"""
    Analyze this person's emotional state and situation:
    "{vent_text}"
    
    Return JSON with:
    {{
        "primary_emotion": "heartbroken/frustrated/anxious/sad/angry",
        "confidence_level": 1-10,
        "key_issues": ["dating", "friendships", "self-esteem"],
        "transformation_type": "subtle/bold/dramatic/natural",
        "energy_level": "low/medium/high",
        "budget_preference": "affordable/mid-range/luxury"
    }}
    """
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        )
        
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"Error in emotional analysis: {e}")
        # Return a default analysis if API fails
        return {
            "primary_emotion": "frustrated",
            "confidence_level": 5,
            "key_issues": ["self-esteem"],
            "transformation_type": "natural",
            "energy_level": "medium",
            "budget_preference": "mid-range"
        }

def get_product_strategy_from_gpt(analysis, original_text):
    prompt = f"""
    Based on this analysis: {analysis}
    Original text: "{original_text}"
    
    Create a strategic search plan. Return JSON:
    {{
        "makeup_searches": [
            {{
                "product_type": "lipstick",
                "specific_terms": ["red lipstick confidence", "bold lip color"],
                "reason": "Bold lips project confidence after heartbreak",
                "priority": 1
            }}
        ],
        "fashion_searches": [
            {{
                "product_type": "blazer",
                "specific_terms": ["black blazer power", "structured blazer"],
                "reason": "Creates powerful silhouette",
                "priority": 1
            }}
        ],
        "quick_wins": [
            "statement earrings",
            "confidence-boosting fragrance"
        ],
        "styling_tips": [
            "Focus on power colors like red and black",
            "Choose structured pieces for confidence"
        ]
    }}
    """
    
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.5
        )
        
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"Error in product strategy: {e}")
        # Return a default strategy if API fails
        return {
            "makeup_searches": [
                {
                    "product_type": "lipstick",
                    "specific_terms": ["red lipstick", "bold lip color"],
                    "reason": "Confidence boost",
                    "priority": 1
                }
            ],
            "fashion_searches": [
                {
                    "product_type": "blazer",
                    "specific_terms": ["black blazer", "structured blazer"],
                    "reason": "Professional look",
                    "priority": 1
                }
            ],
            "quick_wins": ["statement earrings"],
            "styling_tips": ["Focus on confidence-boosting pieces"]
        }
def search_real_products(product_strategy):
    all_products = {
        'makeup': [],
        'fashion': []
    }
    
    # Search makeup products - ONE product per term
    for search in product_strategy['makeup_searches']:
        for term in search['specific_terms']:
            product = search_sephora_single(term)  # Returns ONE product
            
            if product:  # If we found a product
                product['search_reason'] = search['reason']
                product['priority'] = search['priority']
                product['category'] = 'makeup'
                all_products['makeup'].append(product)
    
    # Search fashion products - ONE product per term
    for search in product_strategy['fashion_searches']:
        for term in search['specific_terms']:
            product = search_google_shopping_single(term)  # Returns ONE product
            
            if product:
                product['search_reason'] = search['reason']
                product['priority'] = search['priority']
                product['category'] = 'fashion'
                all_products['fashion'].append(product)
    
    return all_products

def search_sephora_single(search_term):
    params = {
        "q": f"site:sephora.com {search_term}",
        "api_key": os.getenv('SERPAPI_KEY')  # Use environment variable
    }
    
    try:
        response = requests.get("https://serpapi.com/search", params=params)
        results = response.json()
        
        # Get ONLY the first/best result
        organic_results = results.get('organic_results', [])
        if organic_results:
            result = organic_results[0]
            return {
                'name': result.get('title', ''),
                'price': extract_price_from_snippet(result.get('snippet', '')),
                'link': result.get('link', ''),
                'source': 'Sephora',
                'rating': None
            }
    except Exception as e:
        print(f"Error searching Sephora: {e}")
    
    return None


def search_google_shopping_single(search_term):
    params = {
        "q": search_term,
        "tbm": "shop",
        "api_key": os.getenv('SERPAPI_KEY')  # Use environment variable
    }
    
    try:
        response = requests.get("https://serpapi.com/search", params=params)
        results = response.json()
        
        # Get ONLY the first/best result
        shopping_results = results.get('shopping_results', [])
        if shopping_results:
            result = shopping_results[0]
            return {
                'name': result.get('title', ''),
                'price': result.get('price', ''),
                'link': result.get('link', ''),
                'source': result.get('source', 'Unknown'),
                'rating': result.get('rating', None),
                'image': result.get('thumbnail', '')
            }
    except Exception as e:
        print(f"Error searching Google Shopping: {e}")
    
    return None


def curate_with_gpt(raw_products, analysis, original_text):
    prompt = f"""
    Here are real products I found:
    MAKEUP: {json.dumps(raw_products['makeup'][:15], indent=2)}
    FASHION: {json.dumps(raw_products['fashion'][:15], indent=2)}
    
    Based on this person's situation:
    Analysis: {analysis}
    Original text: "{original_text}"
    
    Select the 3-5 best recommendations for each category and create a personalized response:
    
    Return JSON:
    {{
        "message": "Personal message addressing their situation",
        "makeup_recommendations": [
            {{
                "product": "exact product name",
                "price": "price",
                "link": "shopping link",
                "why_perfect": "specific reason for their situation",
                "confidence_boost": "how this helps their confidence",
                "styling_tip": "how to use it"
            }}
        ],
        "outfit_recommendations": [
            {{
                "product": "exact product name",
                "price": "price", 
                "link": "shopping link",
                "why_perfect": "specific reason for their situation",
                "confidence_boost": "how this helps their confidence",
                "styling_tip": "how to wear it"
            }}
        ],
        "quick_wins": [
            "immediate things she can do today"
        ],
        "transformation_plan": "step-by-step glow up plan"
    }}
    
    Make it personal, empowering, and directly address what she's going through!
    """
    
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7
        )
        
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"Error in curation: {e}")
        # Return a default response if API fails
        return {
            "message": "You've got this! Here are some recommendations to help you feel amazing.",
            "makeup_recommendations": [],
            "outfit_recommendations": [],
            "quick_wins": [
                "Take a relaxing bath",
                "Do some light stretching",
                "Listen to your favorite empowering music"
            ],
            "transformation_plan": "Start with small changes that make you feel good, then build from there!"
        }


def extract_price_from_snippet(snippet):
    # Simple price extraction - you'd want to make this more robust
    import re
    price_match = re.search(r'\$[\d,]+\.?\d*', snippet)
    return price_match.group() if price_match else None


# Test route
@app.route('/api/test', methods=['GET'])
def test():
    return jsonify({'message': 'Backend is working! ✨'}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5001)
