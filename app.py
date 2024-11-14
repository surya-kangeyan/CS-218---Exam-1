from flask import Flask, render_template, request, redirect, url_for, session, flash
from decimal import Decimal
import boto3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
from datetime import datetime
import logging
from datetime import datetime, timedelta, timezone
from flask_cors import CORS

app = Flask(__name__, template_folder='pages')
CORS(app, resources={r"/*": {"origins": "http://127.0.0.1:3005"}})  
socketio = SocketIO(app, cors_allowed_origins="*")
app.secret_key = 'skexam1'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        # logging.StreamHandler()
    ]
)


dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
performers_table = dynamodb.Table('contestants')
scores_table = dynamodb.Table('scores')
judges_table = dynamodb.Table('judges')

def is_valid_email(email):
    return email.endswith('@sjsu.edu')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        is_admin = request.form.get('is_admin') == 'on'

        if not is_valid_email(email):
            flash('Invalid email. Please use your @sjsu.edu email.', 'danger')
            return redirect(url_for('signup'))

        response = judges_table.get_item(Key={'id': email})
        if 'Item' in response:
            flash('This email is already registered. Please log in.', 'danger')
            return redirect(url_for('login'))

        existing_admin = judges_table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('is_admin').eq(True)
        ).get('Items', [])

        if existing_admin:
            is_admin = False
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        judges_table.put_item(Item={
            'id': email,
            'name': name,
            'email': email,
            'password': hashed_password,
            'is_admin': is_admin
        })

        flash('Signup successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        response = judges_table.get_item(Key={'id': email})
        judge = response.get('Item')

        if judge and check_password_hash(judge['password'], password):
            session['judge_id'] = email
            session['is_admin'] = judge.get('is_admin', False)
            session['judge_name'] = judge.get('name', 'Unknown')  # Store the judge's name in the session
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            logging.warning(f"Invalid login attempt with email: {email}")
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@app.route('/mark_performance_complete/<performer_id>', methods=['POST'])
def mark_performance_complete(performer_id):
    if not session.get('is_admin'):
        flash('Only the admin can mark performances as complete.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Use timezone-aware datetime (UTC)
        end_time = datetime.now(timezone.utc) + timedelta(minutes=2)  # Adjusted to 2 minutes

        # Update the 'is_performance_over' attribute and add 'end_time' in DynamoDB
        performers_table.update_item(
            Key={'id': performer_id},
            UpdateExpression="SET is_performance_over = :val1, end_time = :val2",
            ExpressionAttributeValues={
                ':val1': True,
                ':val2': end_time.isoformat()
            }
        )

        # Retrieve performer name for notification
        performer = performers_table.get_item(Key={'id': performer_id}).get('Item', {})
        performer_name = performer.get('name', 'Unknown')

        # Emit WebSocket notification to all connected judges with the end time
        socketio.emit(
            'performance_complete',
            {
                'performer_id': performer_id,
                'end_time': end_time.isoformat(),
                'performer_name': performer_name
            },

        )
        print("emitting  voting started emit")
        socketio.emit(
            'voting_started',
            {'performer_name': performer_name}
        )
        flash(f'Performance marked complete for {performer_name}. Judges can now score.', 'success')
        return redirect(url_for('dashboard'))

    except Exception as e:
        flash(f'Error marking performance complete: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/viewer')
def viewer():
    # Fetch performers from the DynamoDB table
    performers = performers_table.scan()['Items']
    ranked_performers = []

    # Iterate over each performer to calculate scores
    for performer in performers:
        # Initialize score counts
        judge1_count = judge2_count = judge3_count = Decimal(0)
        weighted_score = Decimal(0)

        # Fetch scores for the performer
        score_response = scores_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('contestant_id').eq(performer['id'])
        )

        for score in score_response['Items']:
            category_scores = score['category_scores']
            total_category_score = sum(Decimal(s) for s in category_scores)

            if score['judge_id'] == 'sk@sjsu.edu':
                judge1_count = total_category_score
                weighted_score += judge1_count * Decimal('2.0')
            elif score['judge_id'] == 'judge2@sjsu.edu':
                judge2_count = total_category_score
                weighted_score += judge2_count * Decimal('0.5')
            elif score['judge_id'] == 'judge3@sjsu.edu':
                judge3_count = total_category_score
                weighted_score += judge3_count * Decimal('0.5')

        # Update performer with scores
        performer.update({
            'judge1_count': int(judge1_count),
            'judge2_count': int(judge2_count),
            'judge3_count': int(judge3_count),
            'weighted_score': float(weighted_score),
        })

        ranked_performers.append(performer)

    # Sort performers by weighted score in descending order
    ranked_performers.sort(key=lambda x: x['weighted_score'], reverse=True)

    # Assign ranks to performers
    for rank, performer in enumerate(ranked_performers, start=1):
        performer['rank'] = rank

    # Render the viewer template with performers
    return render_template('viewer.html', performers=ranked_performers)
    # Fetch performers from the DynamoDB table


@app.route('/dashboard')
def dashboard():
    if 'judge_id' not in session:
        return redirect(url_for('login'))

    # Fetch performers from the DynamoDB table
    performers = performers_table.scan()['Items']
    ranked_performers = []

    now = datetime.now(timezone.utc)  # Current time in UTC (timezone-aware)

    for performer in performers:
        # Initialize time_left
        time_left = None  # Use None to indicate "Waiting"

        # Check if performance is marked complete
        if performer.get('is_performance_over'):
            end_time = performer.get('end_time')
            if end_time:
                end_time_dt = datetime.fromisoformat(end_time)

                # Ensure end_time_dt is timezone-aware
                if end_time_dt.tzinfo is None:
                    end_time_dt = end_time_dt.replace(tzinfo=timezone.utc)

                time_left = max(0, (end_time_dt - now).total_seconds())
        else:
            time_left = "Waiting"

        performer['time_left'] = time_left

        # Calculate scores and other attributes as needed
        score_response = scores_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('contestant_id').eq(performer['id'])
        )

        judge1_count = judge2_count = judge3_count = Decimal(0)
        weighted_score = Decimal(0)

        for score in score_response['Items']:
            category_scores = score['category_scores']
            total_category_score = sum(Decimal(s) for s in category_scores)

            if score['judge_id'] == 'sk@sjsu.edu':
                judge1_count = total_category_score
                weighted_score += judge1_count * Decimal('2.0')
            elif score['judge_id'] == 'judge2@sjsu.edu':
                judge2_count = total_category_score
                weighted_score += judge2_count * Decimal('0.5')
            elif score['judge_id'] == 'judge3@sjsu.edu':
                judge3_count = total_category_score
                weighted_score += judge3_count * Decimal('0.5')

        # Update performer with scores
        performer.update({
            'judge1_count': int(judge1_count),
            'judge2_count': int(judge2_count),
            'judge3_count': int(judge3_count),
            'weighted_score': float(weighted_score),
        })

        ranked_performers.append(performer)

    # Sort performers by weighted score
    ranked_performers.sort(key=lambda x: x['weighted_score'], reverse=True)

    # Assign ranks to performers
    for rank, performer in enumerate(ranked_performers, start=1):
        performer['rank'] = rank
        performers_table.update_item(
            Key={'id': performer['id']},
            UpdateExpression='SET #r = :r',
            ExpressionAttributeNames={'#r': 'rank'},
            ExpressionAttributeValues={':r': rank}
        )

    # Render the dashboard with performers
    return render_template('dashboard.html', performers=ranked_performers)

from datetime import datetime, timedelta, timezone

from datetime import datetime, timedelta, timezone

@app.route('/edit_score/<performer_id>', methods=['GET', 'POST'])
def edit_score(performer_id):
    if 'judge_id' not in session:
        return redirect(url_for('login'))

    judge_id = session['judge_id']
    judge_email = judge_id  # Assuming judge_id is the email
    judge_name = session.get('judge_name', 'Unknown')

    # Fetch the performer from the database
    performer_response = performers_table.get_item(Key={'id': performer_id})
    performer = performer_response.get('Item')

    if not performer:
        flash('Performer not found.', 'danger')
        return redirect(url_for('dashboard'))

    # Initialize time_left
    time_left = None

    # Check if the scoring window is still open
    if performer.get('is_performance_over'):
        end_time_str = performer.get('end_time')
        if end_time_str:
            end_time = datetime.fromisoformat(end_time_str)

            # Ensure end_time is timezone-aware
            if end_time.tzinfo is None:
                end_time = end_time.replace(tzinfo=timezone.utc)

            # Get current time as timezone-aware
            now = datetime.now(timezone.utc)

            time_left = max(0, (end_time - now).total_seconds())

            if time_left <= 0:
                flash('Scoring time has expired for this performer.', 'danger')
                return redirect(url_for('dashboard'))
        else:
            flash('End time not found for this performer.', 'danger')
            return redirect(url_for('dashboard'))
    else:
        flash('Performance is not marked complete yet.', 'danger')
        return redirect(url_for('dashboard'))

    # Handle form submission
    if request.method == 'POST':
        category_scores = []
        for i in range(1, 6):
            score = request.form.get(f'category_{i}')
            if score is None:
                flash('Please provide scores for all categories.', 'danger')
                return render_template('edit_score.html', performer=performer, time_left=time_left)
            try:
                score = int(score)
                if score < 1 or score > 10:
                    raise ValueError
                category_scores.append(score)
            except ValueError:
                flash('Scores must be integers between 1 and 10.', 'danger')
                return render_template('edit_score.html', performer=performer, time_left=time_left)

        # Save the scores to the database
        scores_table.put_item(
            Item={
                'contestant_id': performer_id,
                'judge_id': judge_email,
                'category_scores': category_scores
            }
        )

        flash('Scores submitted successfully.', 'success')
        return redirect(url_for('dashboard'))

    # Render the scoring form
    return render_template('edit_score.html', performer=performer, time_left=time_left)


@app.route('/delete_contestant/<performer_id>', methods=['POST'])
def delete_contestant(performer_id):
    logging.info('deleting contestant ')
    if not session.get('is_admin'):
        logging.warning(f"Unauthorized delete attempt by {session.get('judge_id')}")
        flash('Only admin can delete contestants.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        logging.info(f"Attempting to delete contestant: {performer_id}")

        performers_table.delete_item(Key={'id': performer_id})

        response = scores_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('contestant_id').eq(performer_id)
        )

        with scores_table.batch_writer() as batch:
            for score in response['Items']:
                batch.delete_item(
                    Key={
                        'contestant_id': performer_id,
                        'judge_id': score['judge_id']
                    }
                )

        flash('Contestant deleted successfully!', 'success')
        logging.info(f"Successfully deleted contestant: {performer_id}")

    except Exception as e:
        logging.error(f"Error deleting contestant {performer_id}: {str(e)}")
        flash(f'Error deleting contestant: {str(e)}', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/add_contestant', methods=['POST'])
def add_contestant():
    if not session.get('is_admin'):
        flash('Only admin can add contestants.', 'danger')
        return redirect(url_for('dashboard'))

    performer_name = request.form['performer_name']
    performer_id = f'performer_{datetime.now().strftime("%Y%m%d%H%M%S")}'
    end_time = datetime.now() + timedelta(minutes=5)

    performers_table.put_item(Item={
        'id': performer_id,
        'name': performer_name,
        'end_time': end_time.isoformat(),
        'is_performance_over': False  

    })
    socketio.emit(
        'performance_started',
        {'performer_name': performer_name}
    )

    logging.info(f'New contestant added: {performer_name} with ID {performer_id}')
    flash(f'Contestant "{performer_name}" added successfully! Judges have 5 minutes to enter scores.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/scoreboard')
def scoreboard():
    if 'judge_id' not in session:
        return redirect(url_for('login'))

    performers = performers_table.scan()['Items']
    ranked_performers = []

    for performer in performers:
        score_response = scores_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('contestant_id').eq(performer['id'])
        )

        judge1_count = judge2_count = judge3_count = Decimal(0)
        weighted_score = Decimal(0)

        for score in score_response['Items']:
            if score['judge_id'] == 'sk@sjsu.edu':
                judge1_count = sum(score['category_scores'])
                weighted_score += judge1_count * Decimal('2.0')
            elif score['judge_id'] == 'judge2@sjsu.edu':
                judge2_count = sum(score['category_scores'])
                weighted_score += judge2_count * Decimal('0.5')
            elif score['judge_id'] == 'judge3@sjsu.edu':
                judge3_count = sum(score['category_scores'])
                weighted_score += judge3_count * Decimal('0.5')

        performer.update({
            'judge1_count': int(judge1_count),
            'judge2_count': int(judge2_count),
            'judge3_count': int(judge3_count),
            'weighted_score': float(weighted_score)
        })

        ranked_performers.append(performer)

    ranked_performers.sort(key=lambda x: x['weighted_score'], reverse=True)

    for rank, performer in enumerate(ranked_performers, start=1):
        performer['rank'] = rank

    return render_template('scoreboard.html', performers=ranked_performers)
@app.route('/logout')
def logout():
    session.pop('judge_id', None)
    session.pop('is_admin', None)
    logging.info('User logged out.')
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=3005)
