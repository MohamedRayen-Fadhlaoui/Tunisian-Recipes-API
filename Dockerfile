# Step 1: Use the official Python image as the base image
FROM python:3.9-slim

# Step 2: Set the working directory inside the container
WORKDIR /app

# Step 3: Copy the requirements file to the container
COPY requirements.txt .

# Step 4: Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Step 5: Copy the entire project into the container
COPY . .

# Step 6: Expose the port that Flask will run on
EXPOSE 5000

# Step 7: Command to run the Flask app
CMD ["python", "app.py"]
