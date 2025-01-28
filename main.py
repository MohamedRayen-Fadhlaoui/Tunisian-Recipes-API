from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_swagger_ui import get_swaggerui_blueprint
from sqlalchemy.dialects.sqlite import JSON


app = Flask(__name__)
CORS(app)

# Database Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///recipes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  
app.config['SECRET_KEY'] = 'your_secret_key'

jwt = JWTManager(app)
db = SQLAlchemy(app)

# Swagger UI Configurations
SWAGGER_URL = '/swagger'
API_DOCS = '/static/swagger.json'  

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_DOCS,
    config={'app_name': "Tunisian Food Recipes API"}
)

# Register Swagger UI blueprint
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    ingredients = db.Column(JSON, nullable=False)  # List of strings stored as JSON
    calories = db.Column(db.Integer, nullable=False)  # Nutritional information
    recipe_type = db.Column(db.String(50), nullable=False)  # Type of recipe (e.g., sweet, spicy, savory)
    preparation_time = db.Column(db.Integer, nullable=False)  # Preparation time in minutes

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    review = db.Column(db.Text, nullable=True)

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    data = request.form
    username = data['username']
    password = generate_password_hash(data['password'])

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists'}), 400

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('home'))

@app.route('/login', methods=['POST'])
def login():
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        username = data.get('username')
        password = data.get('password')

        # Check if username or password is missing
        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400

        # Query the database for the user
        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password, password):
            return jsonify({'message': 'Invalid credentials'}), 400

        session['user_id'] = user.id
        return jsonify({'message': 'Login successful'}), 200

    except Exception as e:
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500


@app.route('/user/delete', methods=['DELETE'])
def delete_user():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    user = User.query.get(session['user_id'])
    if user:
        db.session.delete(user)
        db.session.commit()
        session.pop('user_id', None)
        return jsonify({'message': 'User account deleted successfully'}), 200

    return jsonify({'message': 'User not found'}), 404

@app.route('/recipes', methods=['GET'])
def recipes():
    try:
        recipes = Recipe.query.all()
        return render_template('recipes.html', recipes=recipes)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/recipes/add', methods=['POST'])
@jwt_required()
def add_recipe():
    current_user = get_jwt_identity()

    try:
        data = request.json
        name = data.get('name')
        description = data.get('description')
        ingredients = data.get('ingredients')
        calories = data.get('calories')
        recipe_type = data.get('recipe_type')
        preparation_time = data.get('preparation_time')

        if not all([name, description, ingredients, calories, recipe_type, preparation_time]):
            return jsonify({'message': 'All fields are required'}), 400

        # Add recipe to the database
        new_recipe = Recipe(
            name=name,
            description=description,
            ingredients=ingredients,
            calories=calories,
            recipe_type=recipe_type,
            preparation_time=preparation_time
        )
        db.session.add(new_recipe)
        db.session.commit()

        return jsonify({'message': 'Recipe added successfully', 'recipe_id': new_recipe.id}), 201

    except Exception as e:
        return jsonify({'message': 'Failed to add recipe', 'error': str(e)}), 500



@app.route('/recipes/<int:recipe_id>/edit', methods=['PUT'])
def edit_recipe(recipe_id):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    recipe = Recipe.query.get(recipe_id)
    if not recipe:
        return jsonify({'message': 'Recipe not found'}), 404

    data = request.json
    recipe.name = data.get('name', recipe.name)
    recipe.description = data.get('description', recipe.description)
    db.session.commit()

    return jsonify({'message': 'Recipe updated successfully'}), 200

@app.route('/recipes/<int:recipe_id>/delete', methods=['DELETE'])
def delete_recipe(recipe_id):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    recipe = Recipe.query.get(recipe_id)
    if not recipe:
        return jsonify({'message': 'Recipe not found'}), 404

    db.session.delete(recipe)
    db.session.commit()

    return jsonify({'message': 'Recipe deleted successfully'}), 200

@app.route('/recipes/<int:recipe_id>/review', methods=['POST'])
def add_review(recipe_id):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    recipe = Recipe.query.get(recipe_id)
    if not recipe:
        return jsonify({'message': 'Recipe not found'}), 404

    data = request.json
    rating = data.get('rating')
    review_text = data.get('review', '')

    # Validate rating
    if not isinstance(rating, int) or rating < 1 or rating > 5:
        return jsonify({'message': 'Rating must be an integer between 1 and 5'}), 400

    # Create a new review
    new_review = Review(
        recipe_id=recipe_id,
        user_id=session['user_id'],
        rating=rating,
        review=review_text
    )

    db.session.add(new_review)
    db.session.commit()

    return jsonify({'message': 'Review added successfully'}), 201


@app.route('/reviews/<int:review_id>/edit', methods=['PUT'])
def edit_review(review_id):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    review = Review.query.get(review_id)
    if not review or review.user_id != session['user_id']:
        return jsonify({'message': 'Review not found or unauthorized'}), 404

    data = request.json
    review.rating = data.get('rating', review.rating)
    review.review = data.get('review', review.review)
    db.session.commit()

    return jsonify({'message': 'Review updated successfully'}), 200

@app.route('/reviews/<int:review_id>/delete', methods=['DELETE'])
def delete_review(review_id):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    review = Review.query.get(review_id)
    if not review or review.user_id != session['user_id']:
        return jsonify({'message': 'Review not found or unauthorized'}), 404

    db.session.delete(review)
    db.session.commit()

    return jsonify({'message': 'Review deleted successfully'}), 200

@app.route('/recipes/search', methods=['GET'])
def search_recipes():
    query = request.args.get('query')
    recipes = Recipe.query.filter(Recipe.name.contains(query)).all()
    return render_template('recipes.html', recipes=recipes)

@app.errorhandler(404)
def not_found_error(e):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    #app.run(debug=True)
    app.run(host='0.0.0.0', port=5000) 
