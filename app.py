import os
import random
import json
import threading
from datetime import datetime, UTC, timedelta
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
import logging
import sys
from utility import (
    load_credentials, get_current_credentials, switch_credentials,
    get_media_files, save_tweets_to_file, basename_filter,
    post_tweet, check_credential_health, schedule_and_post_tweets,
    allowed_file,
    credentials, tweets, scheduled_tweets, next_post_time,
    quarantined_credentials
)

# Initialize Flask app
app = Flask(__name__)
socketio = SocketIO(app)
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['UPLOAD_FOLDER'] = 'media/'
app.config['TWEET_STORAGE'] = 'tweets.json'
app.config['CREDENTIALS_FILE'] = 'credentials.xlsx'

# Hardcoded tweets about Chatter
HARDCODED_TWEETS = [
    "In Kenya, speak freely! 😶‍🌫️ #Chatter: no name, no trace, just an alias 🎭. Download now for anonymous chats! 📥 https://codethelabs.com/assets/files/chatter.apk #SpeakFreely Join the movement for digital freedom and express yourself without fear. 🗣️🔥 Stay private, stay secure! 💬😎",
    "No phone 📵, no email 📫, just vibes! #Chatter lets you chat anonymously 🕵️‍♀️. Get it now and join the fun! 📥 https://codethelabs.com/assets/files/chatter.apk #Anonymity Express yourself freely in Kenya without revealing your identity. 🗣️🔥 Stay safe, stay hidden, chat bold! 😎",
    "Be anyone on #Chatter! 😎 Alias + secure password = free speech 🗣️. Download now for private chats! 📥 https://codethelabs.com/assets/files/chatter.apk #DigitalFreedom Join Kenya’s anonymous revolution. No trace, just freedom to speak your mind. 🔥 Stay secure and chat freely! 💬🕶️",
    "Kenya, stay private! 🕵️ #Chatter’s alias signup = total anonymity 🔥. Download now for secure chats! 📥 https://codethelabs.com/assets/files/chatter.apk #ChatterApp Speak without fear, no personal info needed. 🧍‍♂️ Join the movement for digital privacy and freedom! 😎💬🔒",
    "Chat without fear! 😶‍🌫️ #Chatter: no real name 🧍‍♂️, just an alias 🎭. Get it now for anonymity! 📥 https://codethelabs.com/assets/files/chatter.apk #SpeakFreely Kenya, express yourself freely and stay safe. No trace, just vibes. 🗣️🔥 Join the anonymous chat revolution! 😎💬",
    "Freedom to speak! 🗣️ #Chatter’s anonymous signup = secure chats 💬. Download now and join! 📥 https://codethelabs.com/assets/files/chatter.apk #Kenya No personal info, just an alias for total privacy. 😎🔒 Stay hidden and express yourself boldly in Kenya’s digital space! 🔥🕵️",
    "No trace, just talk! 🕵️‍♀️ #Chatter: alias only, no personal info 🚫. Download now for privacy! 📥 https://codethelabs.com/assets/files/chatter.apk #Anonymity Kenya, speak your mind without fear. 🗣️🔥 Stay secure with anonymous chats and join the revolution! 😎💬 Stay private! 🔒",
    "Kenya, express yourself! 😎 #Chatter: alias signup, 100% anonymous 🕶️. Download now for freedom! 📥 https://codethelabs.com/assets/files/chatter.apk #DigitalFreedom No phone, no email, just vibes. 🗣️🔥 Join the secure chat movement and stay private in Kenya! 💬😶‍🌫️🔒",
    "Stay hidden, stay free! 🕵️ #Chatter’s alias chats = no trace 🧍‍♂️. Download now for anonymity! 📥 https://codethelabs.com/assets/files/chatter.apk #ChatterApp Kenya, speak boldly without revealing yourself. 🔥🗣️ Join the anonymous revolution and chat freely! 😎💬🔒",
    "Chat like a ghost! 😶‍🌫️ #Chatter: no phone 📵, no name, just an alias 🎭. Download now! 📥 https://codethelabs.com/assets/files/chatter.apk #SpeakFreely Kenya, stay safe and express freely. 🗣️🔥 No personal info needed for secure chats. Join the movement! 😎💬🔒",
    "Be free in Kenya! 🗣️ #Chatter’s anonymous signup = secure vibes 💬. Download now for privacy! 📥 https://codethelabs.com/assets/files/chatter.apk #Anonymity No real name, just an alias for total freedom. 😎🔒 Speak your mind and stay hidden in Kenya’s digital world! 🔥🕵️",
    "No info, no worries! 🚫 #Chatter: alias only, 100% private 🕵️‍♀️. Download now for freedom! 📥 https://codethelabs.com/assets/files/chatter.apk #DigitalFreedom Kenya, chat without fear or trace. 🗣️🔥 Join the anonymous revolution and express yourself! 😎💬 Stay secure! 🔒",
    "Speak without limits! 🔥 #Chatter’s alias signup = total freedom 🗣️. Download now for privacy! 📥 https://codethelabs.com/assets/files/chatter.apk #ChatterApp Kenya, stay anonymous and chat freely. 😎🕶️ No personal info needed for secure vibes. Join now! 💬🔒 Stay safe! 🕵️",
    "Kenya, stay anonymous! 🕶️ #Chatter: no real name 🧍‍♂️, just vibes 😎. Download now! 📥 https://codethelabs.com/assets/files/chatter.apk #SpeakFreely Express yourself without fear. 🗣️🔥 No phone, no email, just secure chats. Join the revolution! 💬🔒 Stay private! 🕵️",
    "Chat freely, no trace! 🕵️ #Chatter’s alias signup = secure chats 💬. Download now for anonymity! 📥 https://codethelabs.com/assets/files/chatter.apk #Anonymity Kenya, speak boldly without revealing yourself. 😎🔥 Join the anonymous chat movement! 💬🔒 Stay safe and free! 🗣️",
    "Be yourself or anyone! 🎭 #Chatter: no personal info 🚫, just an alias. Download now! 📥 https://codethelabs.com/assets/files/chatter.apk #DigitalFreedom Kenya, chat without fear or trace. 🗣️🔥 Stay private with secure chats. Join the revolution! 😎💬🔒 Stay hidden! 🕵️",
    "Kenya, speak boldly! 🗣️ #Chatter’s anonymous chats = no fear 😶‍🌫️. Download now! 📥 https://codethelabs.com/assets/files/chatter.apk #ChatterApp No real name, just vibes. 😎🔒 Stay secure and express freely in Kenya’s digital space. Join now! 💬🔥 Stay private! 🕵️",
    "No name, no game! 😎 #Chatter: alias signup, 100% private 🕵️‍♀️. Download now! 📥 https://codethelabs.com/assets/files/chatter.apk #SpeakFreely Kenya, chat without revealing yourself. 🗣️🔥 Stay safe with anonymous vibes. Join the revolution! 💬🔒 Stay hidden! 🕶️",
    "Chat without chains! 🔥 #Chatter’s alias = freedom to express 🗣️. Download now! 📥 https://codethelabs.com/assets/files/chatter.apk #Anonymity Kenya, stay private and speak freely. 😎🕵️ No personal info needed for new chats. Join the movement! 💬🔒 Stay safe! 🕶️",
    "Kenya, be free! 🗣️ #Chatter: no phone 📵, no name, just an alias 🎭. Download now! 📥 https://codethelabs.com/assets/files/chatter.apk #DigitalFreedom Speak without fear, stay anonymous. 😎🔥 Join the secure chat revolution in Kenya. 💬🔒 Express yourself boldly! 🕵️"
]

class SocketIOHandler(logging.Handler):
    def emit(self, record):
        log_entry = self.format(record)
        socketio.emit('log_message', {'data': log_entry})

class SocketIOStream:
    def __init__(self, logger):
        self.logger = logger
    def write(self, message):
        self.logger.info(message.strip())
    def flush(self):
        pass

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(SocketIOHandler())

sys.stdout = SocketIOStream(logger)
sys.stderr = SocketIOStream(logger)

app.jinja_env.filters['basename'] = basename_filter

@app.route('/media/<path:filename>')
def serve_media(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/credentials_status', methods=['GET'])
def credentials_status():
    creds = get_current_credentials()
    return jsonify({
        'active_credential': creds['Email'] if creds else 'None',
        'total_credentials': len(credentials)
    })

@app.route('/api/start_system', methods=['POST'])
def start_system():
    if not credentials or not tweets:
        return jsonify({'success': False, 'message': 'Credentials and tweets must be loaded first.'}), 400
    threading.Thread(target=schedule_and_post_tweets, args=(app.config,), daemon=True).start()
    threading.Thread(target=check_credential_health, daemon=True).start()
    return jsonify({'success': True, 'message': 'System started successfully.'})

@app.route('/api/tweets', methods=['GET'])
def get_tweets():
    TWEETS_PER_PAGE = 5
    page = request.args.get('page', 1, type=int)
    total_pages = max(1, (len(tweets) + TWEETS_PER_PAGE - 1) // TWEETS_PER_PAGE)
    page = max(1, min(page, total_pages))
    start = (page - 1) * TWEETS_PER_PAGE
    end = start + TWEETS_PER_PAGE
    return jsonify({
        'tweets': tweets[start:end],
        'page': page,
        'total_pages': total_pages,
        'tweets_per_page': TWEETS_PER_PAGE
    })

@app.route('/api/schedule', methods=['POST'])
def schedule_tweets_api():
    form_data = request.form
    num_posts = form_data.get('num_posts', type=int)
    scheduled_time = form_data.get('scheduled_time')
    if not num_posts or not (1 <= num_posts <= len(HARDCODED_TWEETS)):
        return jsonify({'success': False, 'message': f'Select between 1 and {len(HARDCODED_TWEETS)} posts.'}), 400
    try:
        scheduled_dt = datetime.fromisoformat(scheduled_time).replace(tzinfo=UTC)
        if scheduled_dt <= datetime.now(UTC):
            return jsonify({'success': False, 'message': 'Scheduled time must be in the future.'}), 400
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid scheduled time format.'}), 400
    
    available = [t for t in tweets if not t['posted'] and not t.get('scheduled_time')]
    if len(available) < num_posts:
        return jsonify({'success': False, 'message': 'Not enough available tweets.'}), 400
    
    for tweet in random.sample(available, num_posts):
        tweet['scheduled_time'] = scheduled_dt.isoformat()
        scheduled_tweets.append({**tweet})
    save_tweets_to_file(app.config['TWEET_STORAGE'], tweets)
    return jsonify({'success': True, 'message': f'{num_posts} tweets scheduled successfully!'})

@app.route('/api/post_tweet', methods=['POST'])
def post_tweet_now():
    message = request.form.get('message', '').strip()
    media_file = request.files.get('media')
    if not message:
        return jsonify({'success': False, 'message': 'Please provide a tweet message.'}), 400
    if len(message) > 280:
        return jsonify({'success': False, 'message': 'Message too long (max 280 characters).'}), 400
    
    media_path = None
    if media_file and media_file.filename:
        file_size = len(media_file.read())
        media_file.seek(0)
        if not allowed_file(media_file.filename, file_size):
            return jsonify({'success': False, 'message': 'Invalid media file.'}), 400
        media_path = os.path.join(app.config['UPLOAD_FOLDER'], media_file.filename)
        media_file.save(media_path)
    
    success, posted_tweet_id = post_tweet(app.config, message=message, media_path=media_path, is_instant=True)
    if success:
        new_tweet = {
            'id': max((t['id'] for t in tweets), default=0) + 1,
            'message': message, 'media_path': media_path, 'posted': True,
            'scheduled_time': datetime.now(UTC).isoformat(),
            'tweet_id': posted_tweet_id,
            'posted_by': [get_current_credentials()['Email']],
            'metrics': {'likes': 0, 'retweets': 0, 'replies': 0}
        }
        tweets.append(new_tweet)
        save_tweets_to_file(app.config['TWEET_STORAGE'], tweets)
        return jsonify({'success': True, 'message': f'Tweet posted! View at https://x.com/user/status/{posted_tweet_id}'})
    return jsonify({'success': False, 'message': 'Failed to post tweet.'}), 500

@app.route('/api/send/<int:tweet_id>', methods=['POST'])
def send_tweet(tweet_id):
    status, _ = post_tweet(app.config, tweet_id=tweet_id)
    if status == 'rate_limited':
        return jsonify({'success': False, 'message': 'Rate limit hit.'}), 500
    if status:
        global scheduled_tweets
        scheduled_tweets = [t for t in scheduled_tweets if t['id'] != tweet_id]
        return jsonify({'success': True, 'message': f'Tweet {tweet_id} posted successfully!'})
    return jsonify({'success': False, 'message': 'Failed to post tweet.'}), 500

@app.route('/api/switch_credential', methods=['POST'])
def switch_credential_api():
    switch_credentials()
    creds = get_current_credentials()
    return jsonify({'success': True, 'message': f"Switched to {creds['Email']}"})

@app.route('/api/system_status', methods=['GET'])
def system_status():
    nairobi_time = "Not scheduled"
    if next_post_time:
        utc_time = datetime.fromisoformat(next_post_time)
        nairobi_time = (utc_time + timedelta(hours=3)).strftime('%Y-%m-%d %H:%M:%S')
    return jsonify({
        'next_post_on': nairobi_time,
        'quarantined_credentials': {e: u.isoformat() for e, u in quarantined_credentials.items()}
    })

@app.route('/api/upload', methods=['POST'])
def upload_files():
    if 'credentials' in request.files:
        f = request.files['credentials']
        if f.filename == '':
            return jsonify({'success': False, 'message': 'No selected file for credentials.'}), 400
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_credentials.xlsx')
        f.save(filepath)
        if not load_credentials(filepath, app.config):
            return jsonify({'success': False, 'message': 'Invalid or empty credentials file.'}), 400
        return jsonify({'success': True, 'message': 'Credentials uploaded and verified.'})

    if 'tweets' in request.files:
        f = request.files['tweets']
        if f.filename == '':
            return jsonify({'success': False, 'message': 'No selected file for tweets.'}), 400
        try:
            data = json.loads(f.read().decode('utf-8'))
            if not isinstance(data, list) or not all(isinstance(t, str) for t in data):
                return jsonify({'success': False, 'message': 'Tweets must be an array of strings.'}), 400
            global tweets
            tweets = [
                {'id': i + 1, 'message': msg, 'media_path': None, 'posted': False,
                 'scheduled_time': None, 'tweet_id': None, 'posted_by': [],
                 'metrics': {'likes': 0, 'retweets': 0, 'replies': 0}}
                for i, msg in enumerate(data)
            ]
            save_tweets_to_file(app.config['TWEET_STORAGE'], tweets)
            return jsonify({'success': True, 'message': 'Tweets uploaded and verified.'})
        except (json.JSONDecodeError, Exception) as e:
            return jsonify({'success': False, 'message': f'Error processing tweets file: {e}'}), 500

    return jsonify({'success': False, 'message': 'No files were uploaded.'}), 400

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        'credentials_loaded': len(credentials) > 0,
        'tweets_loaded': len(tweets) > 0,
    })

@app.route('/api/use_default_credentials', methods=['POST'])
def use_default_credentials():
    if request.json.get('use_default'):
        if load_credentials(app.config['CREDENTIALS_FILE'], app.config):
            return jsonify({'success': True, 'message': 'Default credentials loaded.'})
        return jsonify({'success': False, 'message': 'Failed to load default credentials.'})
    global credentials
    credentials = []
    return jsonify({'success': True, 'message': 'Default credentials unchecked.'})

@app.route('/api/use_default_tweets', methods=['POST'])
def use_default_tweets():
    global tweets
    if request.json.get('use_default'):
        media_files = get_media_files(app.config['UPLOAD_FOLDER'])
        tweets = [
            {'id': i + 1, 'message': msg, 'media_path': random.choice(media_files) if media_files else None,
             'posted': False, 'scheduled_time': None, 'tweet_id': None, 'posted_by': [],
             'metrics': {'likes': 0, 'retweets': 0, 'replies': 0}}
            for i, msg in enumerate(HARDCODED_TWEETS)
        ]
        save_tweets_to_file(app.config['TWEET_STORAGE'], tweets)
        return jsonify({'success': True, 'message': 'Default tweets loaded.'})
    tweets = []
    save_tweets_to_file(app.config['TWEET_STORAGE'], tweets)
    return jsonify({'success': True, 'message': 'Default tweets unchecked.'})

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    if os.path.exists(app.config['TWEET_STORAGE']):
        with open(app.config['TWEET_STORAGE'], 'r') as f:
            tweets.extend(json.load(f))
            scheduled_tweets.extend([t for t in tweets if t.get('scheduled_time') and not t.get('posted')])

    if not load_credentials(app.config['CREDENTIALS_FILE'], app.config):
        logger.info("Warning: No valid credentials loaded.")

    socketio.run(app, debug=True)