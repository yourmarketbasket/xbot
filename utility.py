import os
import random
import json
import threading
import time
from datetime import datetime, UTC, timedelta
import tweepy
import pandas as pd
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Constants
EXTRA_HASHTAGS = ["#SocialMedia", "#Tech", "#Community", "#AppOfTheDay", "#StayConnected"]
ALLOWED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.mp4', '.mov'}
MAX_IMAGE_SIZE = 5 * 1024 * 1024
MAX_VIDEO_SIZE = 512 * 1024 * 1024
COOLDOWN_TIME = 30

# Global state
credentials = []
current_credential_index = 0
credential_lock = threading.RLock()
quarantined_credentials = {}
tweet_counts = {}
next_post_time = None
tweets = []
scheduled_tweets = []

def load_credentials(filepath, app_config):
    global credentials, tweet_counts
    logger.info(f"Attempting to load credentials from: {filepath}")
    if not os.path.exists(filepath):
        logger.error(f"Credentials file not found at: {filepath}")
        return []

    try:
        logger.info("Reading Excel file...")
        df = pd.read_excel(filepath, sheet_name='Sheet1')
        logger.info("Excel file read successfully.")

        required_columns = ['Email', 'API KEY', 'API KEY SECRET', 'ACCESS TOKEN', 'ACCESS TOKEN SECRET']
        missing_cols = [col for col in required_columns if col not in df.columns]
        if missing_cols:
            logger.error(f"Missing required columns in credentials file: {', '.join(missing_cols)}")
            return []

        logger.info("Dropping rows with missing values...")
        df.dropna(subset=required_columns, inplace=True)

        if df.empty:
            logger.warning("No valid credentials found in the Excel file after cleaning.")
            return []

        credentials = df[required_columns].to_dict('records')
        tweet_counts = {cred['Email']: {'count': 0, 'date': datetime.now(UTC).date()} for cred in credentials}

        logger.info(f"Successfully loaded and validated {len(credentials)} credentials.")
        logger.debug(f"Loaded credentials: {credentials}")

        return credentials
    except Exception as e:
        logger.error(f"An unexpected error occurred while loading credentials: {e}", exc_info=True)
        return []

def get_current_credentials(index=None):
    with credential_lock:
        if not credentials:
            return None
        return credentials[(index or current_credential_index) % len(credentials)]

def switch_credentials():
    global current_credential_index
    with credential_lock:
        if not credentials:
            return
        current_credential_index = (current_credential_index + 1) % len(credentials)
        creds = get_current_credentials()
        logger.info(f"Switched to credential set {current_credential_index + 1} ({creds['Email']})")

def get_media_files(upload_folder):
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder, exist_ok=True)
        return []
    return [os.path.join(upload_folder, f) for f in os.listdir(upload_folder) if os.path.splitext(f.lower())[1] in ALLOWED_EXTENSIONS]

def save_tweets_to_file(filepath, tweets_data):
    try:
        with open(filepath, 'w') as f:
            json.dump(tweets_data, f, default=str)
    except Exception as e:
        logger.info(f"Error saving tweets to file: {e}")

def basename_filter(path):
    return os.path.basename(path) if path else 'None'

def get_twitter_conn_v1(cred_index):
    creds = get_current_credentials(cred_index)
    if not creds:
        return None, "no_credentials"
    try:
        auth = tweepy.OAuth1UserHandler(creds['API KEY'], creds['API KEY SECRET'], creds['ACCESS TOKEN'], creds['ACCESS TOKEN SECRET'])
        api = tweepy.API(auth, wait_on_rate_limit=False)
        api.verify_credentials()
        logger.info(f"Credentials for {creds['Email']} verified successfully for v1")
        return api, "success"
    except tweepy.errors.TweepyException as e:
        if "429" in str(e):
            quarantined_credentials[creds['Email']] = datetime.now(UTC) + timedelta(hours=12)
            logger.info(f"Rate limit hit (429) for {creds['Email']}. Quarantining for 12 hours.")
            return None, "rate_limited"
        logger.info(f"Error verifying credentials for {creds['Email']} (v1): {e}")
        return None, "error"

def get_twitter_conn_v2(cred_index):
    creds = get_current_credentials(cred_index)
    if not creds:
        return None, "no_credentials"
    try:
        client = tweepy.Client(
            consumer_key=creds['API KEY'], consumer_secret=creds['API KEY SECRET'],
            access_token=creds['ACCESS TOKEN'], access_token_secret=creds['ACCESS TOKEN SECRET']
        )
        client.get_me()
        logger.info(f"OAuth 1.0a v2 client initialized for {creds['Email']}")
        return client, "success"
    except tweepy.errors.TweepyException as e:
        if "429" in str(e):
            quarantined_credentials[creds['Email']] = datetime.now(UTC) + timedelta(hours=12)
            logger.info(f"Rate limit hit (429) for {creds['Email']}. Quarantining for 12 hours.")
            return None, "rate_limited"
        logger.info(f"Error initializing v2 client for {creds['Email']}: {e}")
        return None, "error"

def allowed_file(filename, file_size):
    ext = os.path.splitext(filename.lower())[1]
    if ext not in ALLOWED_EXTENSIONS:
        return False
    if ext in {'.png', '.jpg', '.jpeg'} and file_size > MAX_IMAGE_SIZE:
        return False
    if ext in {'.mp4', '.mov'} and file_size > MAX_VIDEO_SIZE:
        return False
    return True

def _prepare_tweet_text(base_text):
    if random.random() < 0.5:
        base_text += " " + random.choice(EXTRA_HASHTAGS)
    return base_text[:277] + "..." if len(base_text) > 280 else base_text

def _upload_media(client_v1, media_path, email):
    if not media_path or not os.path.exists(media_path):
        return None
    try:
        file_size = os.path.getsize(media_path)
        if not allowed_file(media_path, file_size):
            raise ValueError(f"Invalid media file: {media_path}. Check extension or size.")

        logger.info(f"Uploading media: {media_path} with {email}")
        ext = os.path.splitext(media_path.lower())[1]

        media_upload_func = client_v1.media_upload
        params = {'filename': media_path}
        if ext in {'.mp4', '.mov'}:
            params.update({'chunked': True, 'media_category': 'tweet_video'})

        media = media_upload_func(**params)

        if hasattr(media, 'processing_info') and media.processing_info['state'] != 'succeeded':
            if media.processing_info['state'] == 'pending':
                time.sleep(media.processing_info['check_after_secs'])
                client_v1.get_media_upload_status(media.media_id)
            else:
                raise tweepy.TweepyException(f"Media processing failed: {media.processing_info['error']['message']}")

        logger.info(f"Media uploaded: {media.media_id_string}")
        return [media.media_id_string]
    except (tweepy.TweepyException, ValueError) as e:
        logger.info(f"Error uploading media with {email}: {e}")
        return None

def post_tweet(app_config, tweet_id=None, message=None, media_path=None, is_instant=False, no_cooldown=False):
    """
    Attempts to post a tweet using ONLY the current credential.
    It does NOT loop or switch credentials.
    The calling function is responsible for credential management.
    """
    if not credentials:
        logger.info("Warning: No credentials available.")
        return False, "no_credentials"

    tweet = next((t for t in tweets if t['id'] == tweet_id), None) if tweet_id else None
    if not is_instant and (not tweet or tweet['posted']):
        logger.info(f"Tweet {tweet_id} not found or already posted.")
        return False, "not_found_or_posted"

    creds = get_current_credentials()
    if not creds:
        return False, "no_credentials"
        
    # Check if current credential is legit before attempting
    if creds['Email'] in quarantined_credentials:
        return False, "quarantined"
        
    today = datetime.now(UTC).date()
    if creds['Email'] not in tweet_counts or tweet_counts[creds['Email']]['date'] < today:
        tweet_counts[creds['Email']] = {'count': 0, 'date': today}
    if tweet_counts[creds['Email']]['count'] >= 17:
        logger.info(f"{creds['Email']} has reached daily limit of 17 tweets.")
        quarantined_credentials[creds['Email']] = datetime.now(UTC) + timedelta(hours=24)
        return False, "daily_limit"

    tweet_text = _prepare_tweet_text(message if is_instant else tweet['message'])
    media_path = media_path if is_instant else tweet.get('media_path')

    client_v1, v1_status = get_twitter_conn_v1(current_credential_index)
    client_v2, v2_status = get_twitter_conn_v2(current_credential_index)

    if "rate_limited" in (v1_status, v2_status):
        return False, "rate_limited"
    if not client_v1 or not client_v2:
        return False, "connection_error"

    media_ids = _upload_media(client_v1, media_path, creds['Email'])
    if media_path and not media_ids:
        return False, "media_upload_failed"

    try:
        response = client_v2.create_tweet(text=tweet_text, media_ids=media_ids)
        logger.info(f"Tweet posted by {creds['Email']}: https://x.com/user/status/{response.data['id']}")
        tweet_counts[creds['Email']]['count'] += 1

        if tweet:
            tweet.update({
                'posted': True, 'scheduled_time': datetime.now(UTC).isoformat(),
                'tweet_id': response.data['id'], 'posted_by': [creds['Email']]
            })
            save_tweets_to_file(app_config['TWEET_STORAGE'], tweets)

        if not no_cooldown:
            logger.info(f"Cooldown for {COOLDOWN_TIME} seconds...")
            time.sleep(COOLDOWN_TIME)
        return True, response.data['id']
        
    except tweepy.errors.TweepyException as e:
        if e.response and e.response.status_code == 429:
            quarantined_credentials[creds['Email']] = datetime.now(UTC) + timedelta(hours=12)
            logger.info(f"Rate limit hit (429) for {creds['Email']}. Quarantining for 12 hours.")
            return False, "rate_limited"
        
        logger.info(f"Error posting tweet with {creds['Email']}: {e}")
        return False, "api_error"

def check_credential_health():
    while True:
        now = datetime.now(UTC)
        for email, quarantine_until in list(quarantined_credentials.items()):
            if now >= quarantine_until:
                del quarantined_credentials[email]
                logger.info(f"Removing {email} from quarantine.")
        time.sleep(60)

def schedule_and_post_tweets(app_config):
    global next_post_time
    backoff_time = 60
    while True:
        active_credentials = [c for c in credentials if c['Email'] not in quarantined_credentials]
        if not active_credentials:
            logger.info("All credentials unavailable. Waiting...")
            time.sleep(600)
            continue

        for cred in active_credentials:
            email = cred['Email']
            now = datetime.now(UTC)
            if now.date() > tweet_counts[email]['date']:
                tweet_counts[email] = {'count': 0, 'date': now.date()}

            if tweet_counts[email]['count'] < 17:
                available_tweets = [t for t in tweets if not t['posted'] and not t.get('scheduled_time')]
                if not available_tweets:
                    break

                tweet_to_post = random.choice(available_tweets)
                delay = random.randint(1800, 3600)
                next_post_time = (now + timedelta(seconds=delay)).isoformat()
                logger.info(f"Next post for {email} scheduled around {next_post_time}")
                time.sleep(delay)

                with credential_lock:
                    original_index = current_credential_index
                    try:
                        current_credential_index = [c['Email'] for c in credentials].index(email)
                    except ValueError:
                        continue

                    status, _ = post_tweet(app_config, tweet_id=tweet_to_post['id'])
                    current_credential_index = original_index

                if status == 'rate_limited':
                    logger.info(f"Rate limited. Backing off for {backoff_time} seconds.")
                    time.sleep(backoff_time)
                    backoff_time = min(backoff_time * 2, 3600)
                elif status:
                    logger.info(f"Posted tweet {tweet_to_post['id']} with {email}. Total for {email} today: {tweet_counts[email]['count']}/17")
                    next_post_time = None
                    backoff_time = 60
        time.sleep(600)
