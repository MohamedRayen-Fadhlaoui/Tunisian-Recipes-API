# Tunisian Recipes API

## Overview
The **Tunisian Recipes API** is a Flask-based web service that allows users to explore, manage, and interact with Tunisian recipes. It provides user authentication, recipe management, review functionality, and a recommendation system based on user preferences. The API also includes Swagger UI for interactive documentation.

## Features
- **User Authentication:** JWT-based login, signup, and token refresh.
- **Recipe Management:** Add, edit, delete, and view recipes.
- **Favorites & Recommendations:** Users can favorite recipes and receive personalized recommendations.
- **Reviews & Ratings:** Users can add, edit, and delete reviews for recipes.
- **Search Functionality:** Search recipes by name, ingredients, calories, and preparation time.
- **Swagger UI Documentation:** Interactive API documentation available at `/swagger`.

## Technologies Used
- **Flask** - Web framework
- **Flask SQLAlchemy** - ORM for database management
- **SQLite** - Database
- **Flask-JWT-Extended** - Authentication
- **Flask-CORS** - Cross-Origin Resource Sharing
- **Flask-Swagger-UI** - API documentation

## Installation
### Prerequisites
- Python 3.x installed
- Virtual environment (optional but recommended)

### Steps
1. **Clone the repository:**
   ```sh
   git clone <repository_url>
   cd tunisian-recipes-api
   ```

2. **Create and activate a virtual environment (optional):**
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```sh
   python app.py
   ```
   The API will be available at `http://localhost:5000/`.

## API Endpoints
### Authentication
- `POST /signup` - User registration
- `POST /login` - User login (returns JWT token)
- `POST /refresh` - Refresh access token

### Recipe Management
- `GET /recipes` - Retrieve all recipes
- `POST /recipes/add` - Add a new recipe (JWT required)
- `PUT /recipes/<recipe_id>/edit` - Edit a recipe (JWT required)
- `DELETE /recipes/<recipe_id>/delete` - Delete a recipe (JWT required)

### Reviews
- `POST /recipes/<recipe_id>/review` - Add a review
- `PUT /reviews/<review_id>/edit` - Edit a review
- `DELETE /reviews/<review_id>/delete` - Delete a review

### Favorites & Recommendations
- `POST /recipes/<recipe_id>/favorite` - Mark a recipe as favorite (JWT required)
- `GET /recommendations` - Get personalized recommendations (JWT required)

### Search
- `GET /recipes/search` - Search recipes by name, ingredients, calories, and preparation time

### Swagger Documentation
- `GET /swagger` - Access interactive API documentation

## Database Models
- **User** - Stores user credentials
- **Recipe** - Stores recipe details
- **Review** - Stores user reviews and ratings for recipes
- **UserPreference** - Stores user interactions with recipes (e.g., favorites)

## Error Handling
- `404` - Resource not found
- `401` - Unauthorized (missing or invalid token)
- `500` - Internal server error

## Deployment
To deploy the API on a cloud service or containerized environment:
1. Set environment variables for `JWT_SECRET_KEY` and `SECRET_KEY`.
2. Use `gunicorn` for production:
   ```sh
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```
3. Deploy to a cloud provider like AWS, Heroku, or DigitalOcean.

## License
This project is licensed under the MIT License.

## Contributors
- **Mohamed Rayen Fadhlaoui** - Student

## Contact
For any issues or contributions, please create a GitHub issue or contact `fadhlaouirayen@gmail.com`.

