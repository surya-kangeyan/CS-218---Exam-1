from flask import Flask, render_template, request, redirect, url_for, session, flash
from decimal import Decimal
import boto3
from datetime import datetime
import logging


# Initialize the Flask app and DynamoDB
app = Flask(__name__, template_folder='pages')
app.secret_key = 'skexam1'  # Replace with a secure key
# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()  # This prints logs to the console
    ]
)

# Initialize DynamoDB resource and connect to tables
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
performers_table = dynamodb.Table('contestants')
scores_table = dynamodb.Table('scores')

def is_valid_email(email):
    """Check if the email ends with @sjsu.edu."""
    return email.endswith('@sjsu.edu')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        if is_valid_email(email):
            session['judge_id'] = email
            session['is_admin'] = email == 'sk@sjsu.edu'  # Admin flag
            logging.info(f"Login successful for: {email}")
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            logging.warning(f"Invalid login attempt with email: {email}")
            flash('Invalid email. Please use your @sjsu.edu email.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
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

        ranked_performers.append((performer, weighted_score))

    ranked_performers.sort(key=lambda x: x[1], reverse=True)

    for rank, (performer, _) in enumerate(ranked_performers, start=1):
        performer['rank'] = rank
        performers_table.update_item(
            Key={'id': performer['id']},
            UpdateExpression='SET #r = :r',
            ExpressionAttributeNames={'#r': 'rank'},
            ExpressionAttributeValues={':r': rank}
        )
    return render_template('dashboard.html', performers=[p[0] for p in ranked_performers])

@app.route('/edit_score/<performer_id>', methods=['GET', 'POST'])
def edit_score(performer_id):
    if 'judge_id' not in session:
        return redirect(url_for('login'))

    judge_weights = {'sk@sjsu.edu': Decimal('2.0'), 'judge2@sjsu.edu': Decimal('0.5'), 'judge3@sjsu.edu': Decimal('0.5')}

    if request.method == 'POST':
        category_scores = [Decimal(int(request.form[f'category{i}'])) for i in range(1, 6)]
        if any(score not in [0, 1] for score in category_scores):
            logging.warning(f"Invalid scores entered for performer {performer_id} by {session['judge_id']}")
            flash('Scores must be 0 or 1 for each category.', 'danger')
            return redirect(url_for('edit_score', performer_id=performer_id))

        judge_weight = judge_weights.get(session['judge_id'], Decimal('0.25'))
        weighted_score = sum(category_scores) * judge_weight

        scores_table.put_item(
            Item={
                'contestant_id': performer_id,
                'judge_id': session['judge_id'],
                'category_scores': category_scores,
                'weighted_score': weighted_score,
                'timestamp': datetime.now().isoformat()
            }
        )
        logging.info(f"Scores updated for performer {performer_id} by {session['judge_id']}")
        flash(f'Scores updated for {performer_id}!', 'success')
        return redirect(url_for('dashboard'))

    performer = performers_table.get_item(Key={'id': performer_id}).get('Item', {})
    return render_template('edit_score.html', performer=performer)

@app.route('/delete_contestant/<performer_id>', methods=['POST'])
def delete_contestant(performer_id):
    logging.info('deleting contestant ')
    if not session.get('is_admin'):
        logging.warning(f"Unauthorized delete attempt by {session.get('judge_id')}")
        flash('Only admin can delete contestants.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Add logging to debug
        logging.info(f"Attempting to delete contestant: {performer_id}")

        # Delete the contestant from the contestants table
        performers_table.delete_item(Key={'id': performer_id})

        # Query and delete associated scores
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
    performers_table.put_item(Item={'id': performer_id, 'name': performer_name})

    logging.info(f'New contestant added: {performer_name} with ID {performer_id}')
    flash(f'Contestant "{performer_name}" added successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('judge_id', None)
    session.pop('is_admin', None)
    logging.info('User logged out.')
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3005)
