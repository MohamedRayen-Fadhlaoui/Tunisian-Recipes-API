from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token, decode_token
from flask_swagger_ui import get_swaggerui_blueprint
from sqlalchemy.dialects.sqlite import JSON
from datetime import timedelta, datetime


app = Flask(__name__)


# Database Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///recipes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 30  # In minutes or timedelta
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)


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

class UserPreference(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'), nullable=False)
    preference_type = db.Column(db.String(50), nullable=False)  # Like, View, Favorite, etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Record when interaction occurred

    user = db.relationship('User', backref=db.backref('preferences', lazy=True))
    recipe = db.relationship('Recipe', backref=db.backref('preferences', lazy=True))

class UserInteraction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'), nullable=False)
    rating = db.Column(db.Integer)  # For ratings between 1 and 5
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('interactions', lazy=True))
    recipe = db.relationship('Recipe', backref=db.backref('interactions', lazy=True))



#-------------------------------------------------------------------------------
# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/decode-token', methods=['POST'])
def decode_token_endpoint():
    try:
        token = request.headers.get("Authorization").split(" ")[1]
        decoded = decode_token(token)
        return jsonify(decoded), 200
    except Exception as e:
        return jsonify({'message': 'Invalid token', 'error': str(e)}), 400


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
        data = request.form
        username = data.get('username')
        password = data.get('password')

        # Validate inputs
        if not username or not password:
            return jsonify({'message': 'Username and password are required'}), 400

        # Query the user from the database
        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password, password):
            return jsonify({'message': 'Invalid credentials'}), 400

        # Create a JWT token with user ID as a string
        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))

        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 200

    except Exception as e:
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500

    

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    current_user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id)
    return jsonify({'access_token': new_access_token}), 200

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'message': 'The token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'message': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'message': 'Token is missing'}), 401



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

@app.route('/recipes/<int:recipe_id>/favorite', methods=['POST'])
@jwt_required()
def favorite_recipe(recipe_id):
    current_user_id = get_jwt_identity()
    
    # Check if the recipe already exists in UserPreferences (like a favorite)
    existing_preference = UserPreference.query.filter_by(user_id=current_user_id, recipe_id=recipe_id, preference_type='favorite').first()
    
    if existing_preference:
        return jsonify({'message': 'Recipe already marked as favorite'}), 400
    
    new_preference = UserPreference(
        user_id=current_user_id,
        recipe_id=recipe_id,
        preference_type='favorite'
    )
    
    db.session.add(new_preference)
    db.session.commit()
    
    return jsonify({'message': 'Recipe marked as favorite'}), 201

@app.route('/recommendations', methods=['GET'])
@jwt_required()
def get_recommendations():
    current_user_id = get_jwt_identity()
    
    # Get the list of favorite or interacted recipes for the current user
    user_preferences = UserPreference.query.filter_by(user_id=current_user_id, preference_type='favorite').all()
    favorite_recipe_ids = [preference.recipe_id for preference in user_preferences]
    
    # Find users who liked similar recipes
    similar_users = UserPreference.query.filter(UserPreference.recipe_id.in_(favorite_recipe_ids)).all()
    
    # Get all recipes liked by those similar users, excluding the current user's favorites
    recommended_recipe_ids = set()
    for user in similar_users:
        if user.user_id != current_user_id:  # Avoid recommending recipes that the current user already interacted with
            recommended_recipe_ids.add(user.recipe_id)
    
    # Retrieve recommended recipes based on recipe IDs
    recommended_recipes = Recipe.query.filter(Recipe.id.in_(recommended_recipe_ids)).all()
    
    # Prepare the response with recommended recipes
    recommendations = [{
        'id': recipe.id,
        'name': recipe.name,
        'ingredients': recipe.ingredients,
        'calories': recipe.calories,
        'recipe_type': recipe.recipe_type,
        'preparation_time': recipe.preparation_time
    } for recipe in recommended_recipes]
    
    return jsonify(recommendations), 200

@app.route('/recipes', methods=['GET'])
def recipes():
    try:
        recipes = Recipe.query.all()
        return render_template('recipes.html', recipes=recipes)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

from flask_jwt_extended import jwt_required, get_jwt_identity

@app.route('/recipes/add', methods=['POST'])
@jwt_required()
def add_recipe():
    current_user_id = get_jwt_identity()  # Get the current user ID from the JWT

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
    query = request.args.get('query')  # Search by recipe name
    ingredients = request.args.get('ingredients')  # Search by multiple ingredients to include
    exclude_ingredients = request.args.get('exclude_ingredients')  # Search by ingredients to exclude
    calories = request.args.get('calories', type=int)  # Search by calories (less or equal to)
    preparation_time = request.args.get('preparation_time', type=int)  # Search by preparation time (less or equal to)

    query_filter = Recipe.query
    
    # Filter by recipe name (if provided)
    if query:
        query_filter = query_filter.filter(Recipe.name.contains(query))
    
    # Filter by included ingredients (if provided)
    if ingredients:
        ingredients_list = ingredients.split(',')  # Split ingredients by commas
        for ingredient in ingredients_list:
            query_filter = query_filter.filter(Recipe.ingredients.contains(ingredient.strip()))  # strip spaces
    
    # Filter by excluded ingredients (if provided)
    if exclude_ingredients:
        exclude_ingredients_list = exclude_ingredients.split(',')  # Split ingredients by commas
        for exclude_ingredient in exclude_ingredients_list:
            query_filter = query_filter.filter(~Recipe.ingredients.contains(exclude_ingredient.strip()))  # Exclude recipes containing these ingredients
    
    # Filter by calories (if provided)
    if calories is not None:
        query_filter = query_filter.filter(Recipe.calories <= calories)
    
    # Filter by preparation time (if provided)
    if preparation_time is not None:
        query_filter = query_filter.filter(Recipe.preparation_time <= preparation_time)
    
    # Get the filtered recipes
    recipes = query_filter.all()

    return jsonify([{
        'id': recipe.id,
        'name': recipe.name,
        'ingredients': recipe.ingredients,
        'calories': recipe.calories,
        'recipe_type': recipe.recipe_type,
        'preparation_time': recipe.preparation_time
    } for recipe in recipes]), 200





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
