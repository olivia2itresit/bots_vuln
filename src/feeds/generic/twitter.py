import tweepy
import sqlite3
import csv
import os
 
# Auth
BEARER_TOKEN1="AAAAAAAAAAAAAAAAAAAAAByM3gEAAAAAxDtbp9ULrgk%2BunPbqrsymv6%2FYwY%3DOphaJ5Pmrb3iVWQo0W7qZiogTrzWcOTDxIZyfy4UoDJEDjDw3H"
BEARER_TOKEN2="AAAAAAAAAAAAAAAAAAAAAPe93gEAAAAAuoaKLjS7C4sgxdUHHiEn%2BLdOApg%3Dof4AhKUo07BW7ytfHc7RFG7iW2dVleAIUYNgpmekGvRidgYnnr"
DB = "db/vulns.db"

# Query
query = f"""
("CVE-" OR "0day" OR "exploit" OR "exploiting" OR "actively exploited" OR "PATCH NOW" OR "patch now" OR "PATCH" OR "patch" OR "Known Exploited Vulnerabilities") (from:thehackersnews OR from:cert_fr OR from:CISAgov OR from:H4ckmanac OR from:CISACyber) -is:retweet
"""

CSV_FILE = "src/generic/tweets_data/tweets.csv"
csv_header = ["id", "date", "text"]

def try_to_fetch_tweets(query):
    try:
        return fetch_tweets(query, BEARER_TOKEN1)
    except Exception as e:
        try:
            return fetch_tweets(query, BEARER_TOKEN2)
        except Exception as e:
            print(f"Error fetching tweets: {e}")
            raise Exception("Both Twitter API tokens failed.")
            return None


def fetch_tweets(query, bearer_token): 
    client = tweepy.Client(bearer_token=bearer_token)
    tweets = client.search_recent_tweets(query=query, max_results=10, tweet_fields=["id","created_at","text"])
    for tweet in tweets.data:
        tweet.text = tweet.text.replace("\n", " ").replace("\r", " ")
    return tweets


def check_techs(tweets):
    pass


def to_csv(tweets):
    with open(CSV_FILE, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for tweet in tweets.data:

            # Si le fichier est vide, on écrit l'en-tête
            if f.tell() == 0:
                writer.writerow(csv_header)
        
            # Sauvegarde CSV
            writer.writerow([tweet.id, str(tweet.created_at), tweet.text])


def to_db(tweets):
    # Connexion DB
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS tweets (id TEXT PRIMARY KEY, date TEXT, text TEXT, notified INTEGER)")

    for tweet in tweets.data:
        try:
            cur.execute("INSERT INTO tweets VALUES (?,?,?,?) ON CONFLICT(id) DO NOTHING", (tweet.id, str(tweet.created_at), tweet.text, 0))
            conn.commit()
    
        except Exception as e:
            print(f"Error saving tweet {tweet.id} to DB: {e}")
            continue

    conn.close()


def main():
        if not os.path.exists(DB):
                print(f"Warning: Database file '{DB}' does not exist or path is inaccessible.")
                exit(1)
        tweets = try_to_fetch_tweets(query)
        if tweets.data:
            #TODO Would need a token-against processing to only store tweets relevants to specific tecnologies
            #tweets = check_techs(tweets)
            to_csv(tweets)
            to_db(tweets)

if __name__ == "__main__":
    main()