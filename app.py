import os
import random
import json
import threading
import time
from datetime import datetime, UTC, timedelta
import tweepy
from flask import Flask, render_template, request, jsonify, send_from_directory
import pandas as pd

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['UPLOAD_FOLDER'] = 'media/'
app.config['TWEET_STORAGE'] = 'tweets.json'
app.config['CREDENTIALS_FILE'] = 'credentials.xlsx'

# Extra hashtags for engagement
EXTRA_HASHTAGS = ["#SocialMedia", "#Tech", "#Community", "#AppOfTheDay", "#StayConnected"]

# Allowed media extensions and size limits
ALLOWED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.mp4', '.mov'}
MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5MB
MAX_VIDEO_SIZE = 512 * 1024 * 1024  # 512MB

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

# Load credentials from Excel file
def load_credentials():
    try:
        if not os.path.exists(app.config['CREDENTIALS_FILE']):
            print(f"Credentials file {app.config['CREDENTIALS_FILE']} not found.")
            return []
        df = pd.read_excel(app.config['CREDENTIALS_FILE'], sheet_name='Sheet1')
        required_columns = ['Email', 'API KEY', 'API KEY SECRET', 'ACCESS TOKEN', 'ACCESS TOKEN SECRET']
        if not all(col in df.columns for col in required_columns):
            print(f"Missing required columns in {app.config['CREDENTIALS_FILE']}: {required_columns}")
            return []
        credentials = df[required_columns].to_dict('records')
        if not credentials:
            print("No credentials found in the Excel file.")
            return []
        print(f"Loaded {len(credentials)} credentials from {app.config['CREDENTIALS_FILE']}")
        return credentials
    except Exception as e:
        print(f"Error loading credentials from {app.config['CREDENTIALS_FILE']}: {str(e)}")
        return []

# Global credentials management
credentials = load_credentials()
current_credential_index = 0
credential_lock = threading.Lock()
quarantined_credentials = {} # email -> quarantine_until_datetime

# Get current Twitter/X API credentials
def get_current_credentials(index=None):
    global credentials, current_credential_index
    with credential_lock:
        if not credentials:
            print("No credentials available.")
            return None
        if index is None:
            index = current_credential_index
        return credentials[index % len(credentials)]

# Switch to next credentials
def switch_credentials():
    global current_credential_index
    with credential_lock:
        if not credentials:
            print("No credentials to switch to.")
            return
        current_credential_index = (current_credential_index + 1) % len(credentials)
        print(f"Switched to credential set {current_credential_index + 1} ({credentials[current_credential_index]['Email']})")

# Get list of media files from media/ directory
def get_media_files():
    media_dir = app.config['UPLOAD_FOLDER']
    if not os.path.exists(media_dir):
        print(f"Media directory {media_dir} does not exist.")
        os.makedirs(media_dir, exist_ok=True)
        return []
    media_files = [
        os.path.join(media_dir, f) for f in os.listdir(media_dir)
        if os.path.splitext(f.lower())[1] in ALLOWED_EXTENSIONS
    ]
    return media_files

# Save tweets to file
def save_tweets_to_file(tweets):
    try:
        with open(app.config['TWEET_STORAGE'], 'w') as f:
            json.dump(tweets, f, default=str)
    except Exception as e:
        print(f"Error saving tweets to file: {str(e)}")

# Custom Jinja2 filter for basename
def basename_filter(path):
    return os.path.basename(path) if path else 'None'

# Load initial tweet storage
media_files = get_media_files()
tweets = [
    {
        'id': i + 1,
        'message': msg,
        'media_path': random.choice(media_files) if media_files else None,
        'posted': False,
        'scheduled_time': None,
        'tweet_id': None,
        'posted_by': [],  # List to store emails of accounts that posted the tweet
        'metrics': {'likes': 0, 'retweets': 0, 'replies': 0}
    } for i, msg in enumerate(HARDCODED_TWEETS)
]

# Initialize scheduled tweets array
scheduled_tweets = []

# Save initial tweets
save_tweets_to_file(tweets)

# Register custom Jinja2 filter
app.jinja_env.filters['basename'] = basename_filter

# Twitter/X API connections
def get_twitter_conn_v1(credential_index):
    creds = get_current_credentials(credential_index)
    if not creds:
        print("No credentials available for v1 connection.")
        return None
    try:
        auth = tweepy.OAuth1UserHandler(
            creds['API KEY'],
            creds['API KEY SECRET'],
            creds['ACCESS TOKEN'],
            creds['ACCESS TOKEN SECRET']
        )
        api = tweepy.API(auth, wait_on_rate_limit=False)
        api.verify_credentials()
        print(f"Credentials for {creds['Email']} verified successfully for v1")
        return api
    except tweepy.TweepyException as e:
        print(f"Error verifying credentials for {creds['Email']} (v1): {str(e)}")
        return None

def get_twitter_conn_v2(credential_index):
    creds = get_current_credentials(credential_index)
    if not creds:
        print("No credentials available for v2 connection.")
        return None
    try:
        client = tweepy.Client(
            consumer_key=creds['API KEY'],
            consumer_secret=creds['API KEY SECRET'],
            access_token=creds['ACCESS TOKEN'],
            access_token_secret=creds['ACCESS TOKEN SECRET']
        )
        client.get_me()
        print(f"OAuth 1.0a v2 client initialized for {creds['Email']}")
        return client
    except tweepy.TweepyException as e:
        print(f"Error initializing v2 client for {creds['Email']}: {str(e)}")
        return None

# Validate file extension and size
def allowed_file(filename, file_size):
    ext = os.path.splitext(filename.lower())[1]
    if ext not in ALLOWED_EXTENSIONS:
        return False
    if ext in {'.png', '.jpg', '.jpeg'} and file_size > MAX_IMAGE_SIZE:
        return False
    if ext in {'.mp4', '.mov'} and file_size > MAX_VIDEO_SIZE:
        return False
    return True

# Serve media files
@app.route('/media/<path:filename>')
def serve_media(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# API endpoint for credentials status
@app.route('/api/credentials_status', methods=['GET'])
def credentials_status():
    creds = get_current_credentials()
    return jsonify({
        'active_credential': creds['Email'] if creds else 'None',
        'total_credentials': len(credentials)
    })

# Post tweet with optional media
def post_tweet(tweet_id=None, message=None, media_path=None, is_instant=False):
    global current_credential_index
    if not credentials:
        print("Warning: No credentials available.")
        return False, None

    tweet = None
    if is_instant and message:
        tweet_text = message
    else:
        tweet = next((t for t in tweets if t['id'] == tweet_id), None)
        if not tweet or tweet['posted']:
            print(f"Tweet {tweet_id} not found or already posted.")
            return False, None
        tweet_text = tweet['message']
        media_path = tweet['media_path']

    if random.random() < 0.5:
        tweet_text += " " + random.choice(EXTRA_HASHTAGS)
    if len(tweet_text) > 280:
        tweet_text = tweet_text[:277] + "..."

    posted_tweet_ids = []
    posted_emails = []
    
    for _ in range(len(credentials)):
        creds = get_current_credentials()
        if not creds:
            switch_credentials()
            continue

        client_v1 = get_twitter_conn_v1(current_credential_index)
        client_v2 = get_twitter_conn_v2(current_credential_index)

        if not client_v1 or not client_v2:
            print(f"Failed to initialize Twitter clients for {creds['Email']}. Switching credentials.")
            switch_credentials()
            continue

        media_ids = None
        if media_path and os.path.exists(media_path):
            try:
                file_size = os.path.getsize(media_path)
                if not allowed_file(media_path, file_size):
                    raise ValueError(f"Invalid media file: {media_path}. Check extension or size.")
                print(f"Uploading media: {media_path} with {creds['Email']}")
                media = client_v1.media_upload(filename=media_path)
                media_ids = [media.media_id_string]
                print(f"Media uploaded: {media.media_id_string}")
            except (tweepy.TweepyException, ValueError) as e:
                print(f"Error uploading media with {creds['Email']}: {str(e)}")
                switch_credentials()
                continue

        try:
            response = client_v2.create_tweet(text=tweet_text, media_ids=media_ids)
            print(f"Tweet posted by {creds['Email']}: https://x.com/user/status/{response.data['id']}")
            posted_tweet_ids.append(response.data['id'])
            posted_emails.append(creds['Email'])
        except tweepy.TweepyException as e:
            if e.response and e.response.status_code == 429:
                print(f"Rate limit hit (429) for {creds['Email']}. Switching credentials.")
            else:
                print(f"Error posting tweet with {creds['Email']}: {str(e)}")
            switch_credentials()
            continue

        # Switch credential after each successful post to distribute load
        switch_credentials()

        if tweet:
            tweet['posted'] = True
            tweet['scheduled_time'] = datetime.now(UTC).isoformat()
            tweet['tweet_id'] = posted_tweet_ids[0]
            tweet['posted_by'] = posted_emails
            save_tweets_to_file(tweets)
        return True, posted_tweet_ids[0]

    print(f"Failed to post tweet. All credentials failed.")
    return False, None

# Credential health check
def check_credential_health():
    global quarantined_credentials
    while True:
        now = datetime.now(UTC)
        for email, quarantine_until in list(quarantined_credentials.items()):
            if now >= quarantine_until:
                print(f"Removing {email} from quarantine.")
                del quarantined_credentials[email]

        for cred in credentials:
            email = cred['Email']
            if email in quarantined_credentials:
                continue

            try:
                client_v2 = get_twitter_conn_v2([c['Email'] for c in credentials].index(email))
                if not client_v2:
                    raise tweepy.TweepyException("Failed to initialize client")
                client_v2.get_me()
            except tweepy.TweepyException as e:
                if hasattr(e, 'response') and e.response and e.response.status_code == 429:
                    quarantine_until = now + timedelta(hours=1)
                    quarantined_credentials[email] = quarantine_until
                    print(f"Credential {email} hit rate limit (429). Quarantined until {quarantine_until.isoformat()}.")
                else:
                    print(f"Error with credential {email}: {e}")

        time.sleep(3600) # Check health every hour

# Background thread to schedule and post 17 tweets per day per credential
def schedule_and_post_tweets():
    global scheduled_tweets
    posted_counts = {cred['Email']: {'count': 0, 'date': datetime.now(UTC).date()} for cred in credentials}
    next_post_time = None

    while True:
        now = datetime.now(UTC)
        
        active_credentials = [c for c in credentials if c['Email'] not in quarantined_credentials]
        if not active_credentials:
            time.sleep(600)
            continue

        # Iterate through each active credential to check and post
        for cred in active_credentials:
            email = cred['Email']

            # Reset daily counter
            if now.date() > posted_counts[email]['date']:
                posted_counts[email]['count'] = 0
                posted_counts[email]['date'] = now.date()

            if posted_counts[email]['count'] < 17:
                available_tweets = [t for t in tweets if not t['posted'] and t['scheduled_time'] is None]
                if available_tweets:
                    tweet_to_post = random.choice(available_tweets)

                    delay = random.randint(1800, 3600) # 30 to 60 minutes
                    next_post_time = (now + timedelta(seconds=delay)).isoformat()
                    print(f"Next post scheduled around {next_post_time} with {email}")
                    time.sleep(delay)

                    # Use the specific credential for posting
                    original_index = current_credential_index
                    try:
                        cred_index = [c['Email'] for c in credentials].index(email)
                        with credential_lock:
                            global current_credential_index
                            current_credential_index = cred_index
                    except ValueError:
                        continue

                    success, _ = post_tweet(tweet_id=tweet_to_post['id'])

                    with credential_lock:
                        current_credential_index = original_index

                    if success:
                        posted_counts[email]['count'] += 1
                        print(f"Posted tweet {tweet_to_post['id']} with {email}. Total for {email} today: {posted_counts[email]['count']}/17")
                        next_post_time = None # Reset after posting

        time.sleep(600)

# Start background threads
threading.Thread(target=check_credential_health, daemon=True).start()
threading.Thread(target=schedule_and_post_tweets, daemon=True).start()

# API endpoint to get all tweets
@app.route('/api/tweets', methods=['GET'])
def get_tweets():
    global tweets
    TWEETS_PER_PAGE = 5
    page = request.args.get('page', 1, type=int)
    
    all_tweets = tweets
    total_pages = max(1, (len(all_tweets) + TWEETS_PER_PAGE - 1) // TWEETS_PER_PAGE)
    page = max(1, min(page, total_pages))
    start = (page - 1) * TWEETS_PER_PAGE
    end = start + TWEETS_PER_PAGE
    
    return jsonify({
        'tweets': all_tweets[start:end],
        'page': page,
        'total_pages': total_pages,
        'tweets_per_page': TWEETS_PER_PAGE
    })

# API endpoint to schedule tweets manually
@app.route('/api/schedule', methods=['POST'])
def schedule_tweets():
    global tweets, scheduled_tweets
    form_data = request.form
    num_posts = form_data.get('num_posts', type=int)
    scheduled_time = form_data.get('scheduled_time')
    
    if not num_posts or num_posts < 1 or num_posts > len(HARDCODED_TWEETS):
        return jsonify({'success': False, 'message': f'Please select between 1 and {len(HARDCODED_TWEETS)} posts.'}), 400
    
    try:
        scheduled_dt = datetime.fromisoformat(scheduled_time)
        scheduled_dt = scheduled_dt.replace(tzinfo=UTC)
        now = datetime.now(UTC)
        if scheduled_dt <= now:
            return jsonify({'success': False, 'message': 'Scheduled time must be in the future.'}), 400
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid scheduled time format.'}), 400
    
    available_tweets = [t for t in tweets if not t['posted'] and t['scheduled_time'] is None]
    if len(available_tweets) < num_posts:
        return jsonify({'success': False, 'message': 'Not enough available tweets to schedule.'}), 400
    
    selected_tweets = random.sample(available_tweets, num_posts)
    for tweet in selected_tweets:
        tweet['scheduled_time'] = scheduled_dt.isoformat()
        scheduled_tweets.append({
            'id': tweet['id'],
            'message': tweet['message'],
            'media_path': tweet['media_path'],
            'scheduled_time': tweet['scheduled_time'],
            'posted': False
        })
        print(f"Scheduled tweet {tweet['id']} at {scheduled_dt}")
    
    save_tweets_to_file(tweets)
    
    return jsonify({'success': True, 'message': f'{num_posts} tweets scheduled successfully!'})

# API endpoint to post tweet immediately
@app.route('/api/post_tweet', methods=['POST'])
def post_tweet_now():
    global tweets
    form_data = request.form
    message = form_data.get('message')
    media_file = request.files.get('media')
    media_path = None
    
    if not message or not message.strip():
        return jsonify({'success': False, 'message': 'Please provide a tweet message.'}), 400
    
    if len(message) > 280:
        return jsonify({'success': False, 'message': f'Message too long (max 280 characters): {message[:50]}...'}), 400
    
    if media_file and media_file.filename:
        file_size = len(media_file.read())
        media_file.seek(0)
        if not allowed_file(media_file.filename, file_size):
            return jsonify({'success': False, 'message': f'Invalid media file: {media_file.filename}. Must be PNG/JPG/MP4/MOV, max 5MB for images, 512MB for videos.'}), 400
        try:
            media_path = os.path.join(app.config['UPLOAD_FOLDER'], media_file.filename)
            media_file.save(media_path)
        except Exception as e:
            print(f"Error saving file {media_file.filename}: {str(e)}")
            return jsonify({'success': False, 'message': f'Error saving media file: {str(e)}'}), 500
    
    success, posted_tweet_id = post_tweet(message=message, media_path=media_path, is_instant=True)
    if success:
        max_id = max((t['id'] for t in tweets), default=0)
        # Find the email of the credential that successfully posted the tweet
        successful_credential_email = "Unknown"
        if posted_tweet_id:
            # This is a simplification. In a real-world scenario, you'd get this from post_tweet
            successful_credential_email = get_current_credentials()['Email']

        tweets.append({
            'id': max_id + 1,
            'message': message,
            'media_path': media_path,
            'posted': True,
            'scheduled_time': datetime.now(UTC).isoformat(),
            'tweet_id': posted_tweet_id,
            'posted_by': [successful_credential_email],
            'metrics': {'likes': 0, 'retweets': 0, 'replies': 0}
        })
        save_tweets_to_file(tweets)
        return jsonify({'success': True, 'message': f'Tweet posted successfully! View it at https://x.com/user/status/{posted_tweet_id}'})
    return jsonify({'success': False, 'message': 'Failed to post tweet.'}), 500

# API endpoint to send tweet immediately
@app.route('/api/send/<int:tweet_id>', methods=['POST'])
def send_tweet(tweet_id):
    success, posted_tweet_id = post_tweet(tweet_id)
    if success:
        global scheduled_tweets
        scheduled_tweets[:] = [t for t in scheduled_tweets if t['id'] != tweet_id]
        return jsonify({'success': True, 'message': f'Tweet {tweet_id} posted successfully!'})
    return jsonify({'success': False, 'message': f'Failed to post tweet {tweet_id}.'}), 500

# API endpoint for system status
@app.route('/api/system_status', methods=['GET'])
def system_status():
    global next_post_time
    nairobi_time = "Not scheduled"
    if next_post_time:
        utc_time = datetime.fromisoformat(next_post_time)
        nairobi_tz = timedelta(hours=3)
        nairobi_time = (utc_time + nairobi_tz).strftime('%Y-%m-%d %H:%M:%S')

    return jsonify({
        'next_post_on': nairobi_time,
        'quarantined_credentials': list(quarantined_credentials.keys())
    })

# Main route
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    if not credentials:
        print("Warning: No valid credentials loaded. Check credentials.xlsx file.")
    app.run(debug=True)