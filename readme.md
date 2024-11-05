# CS -218 Exam 1 : Scoring System

This web-based application manages and scores contestants at San Jose State University (SJSU) for Midterm - 1. It allows judges to register, log in, and score contestants in real time.

## Features

- Judge registration and login system with @sjsu.edu email validation
- Admin functionality for managing contestants
- Real-time scoring system with weighted scores
- Dashboard displaying contestant rankings
- Time-limited voting (5 minutes) for each contestant

## Technologies Used

- Python 3.x
- Flask
- AWS DynamoDB
- AWS EC2
- HTML/CSS
- JavaScript

## Setup and Installation

1. Clone the repository
2. Install the required dependencies:
    ```pip install flask boto3 werkzeug```
3. Set up AWS credentials for DynamoDB access
4. Run the application:
    ```python3 app.py```


## Usage

- Judges can register using their @sjsu.edu email addresses
- Admins can add and delete contestants
- Judges have 5 minutes to score each contestant after they are added
- The dashboard displays real-time rankings based on weighted scores

## File Structure

- `app.py`: Main Flask application
- `pages/`: Directory containing HTML templates
- `dashboard.html`: Main dashboard view
- `login.html`: Login page
- `signup.html`: Registration page
- `edit_score.html`: Scoring page for judges

## Scoring System

- Judges can score contestants in 5 categories
- Scores are weighted differently for each judge:
- SK (admin): 2.0
- Judge 2: 0.5
- Judge 3: 0.5

## Sample Credentials

- sk@sjsu.edu, 1234
- judge2@sjsu.edu, 1234
- judge3@sjsu.edu, 1234

## Security

- Passwords are hashed using pbkdf2:sha256 method
- Session-based authentication is used
- Only admin users can add or delete contestants

## Logging

- The application logs important events and errors to 'app.log'

## Note

This application is designed for use within SJSU and requires @sjsu.edu email addresses for registration.

For any issues or feature requests, please contact suryakangeyan kandasamy gowdaman (017407299).
