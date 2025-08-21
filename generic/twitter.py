import tweepy
import sqlite3
import csv
 
# Auth
BEARER_TOKEN1="AAAAAAAAAAAAAAAAAAAAAByM3gEAAAAAxDtbp9ULrgk%2BunPbqrsymv6%2FYwY%3DOphaJ5Pmrb3iVWQo0W7qZiogTrzWcOTDxIZyfy4UoDJEDjDw3H"
BEARER_TOKEN2="AAAAAAAAAAAAAAAAAAAAAPe93gEAAAAAuoaKLjS7C4sgxdUHHiEn%2BLdOApg%3Dof4AhKUo07BW7ytfHc7RFG7iW2dVleAIUYNgpmekGvRidgYnnr"
# Query
query = f"""
("CVE-" OR "0day" OR "exploit" OR "PATCH NOW" OR "patch now") (from:thehackersnews OR from:cert_fr OR from:CISAgov OR from:H4ckmanac) -is:retweet
"""

csv_file = "tweets.csv"
csv_header = ["id", "date", "text"]

def try_to_fetch_tweets(query):
    try:
        return fetch_tweets(query, BEARER_TOKEN1)
    except Exception as e:
        try:
            return fetch_tweets(query, BEARER_TOKEN2)
        except Exception as e:
            print(f"Error fetching tweets: {e}")
            return None


def fetch_tweets(query, bearer_token): 
    client = tweepy.Client(bearer_token=bearer_token)
    tweets = client.search_recent_tweets(query=query, max_results=10, tweet_fields=["id","created_at","text"])
    return tweets

def to_csv(tweets):
    # On ouvre le CSV en mode append pour ne pas écraser les données déjà existantes
    with open(csv_file, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for tweet in tweets.data:

            # Si le fichier est vide, on écrit l'en-tête
            if f.tell() == 0:
                writer.writerow(csv_header)
        
            # Sauvegarde CSV
            writer.writerow([tweet.id, str(tweet.created_at), tweet.text])


def to_db(tweets):
    # Connexion DB
    conn = sqlite3.connect("cves.db")
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS tweets (id TEXT PRIMARY KEY, date TEXT, text TEXT)")

    for tweet in tweets.data:
        # Sauvegarde SQLite
        try:
            cur.execute("INSERT INTO tweets VALUES (?,?,?)", (tweet.id, str(tweet.created_at), tweet.text))
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    conn.close()


def main():
        tweets = try_to_fetch_tweets(query)
        if tweets.data:
            to_csv(tweets)
            to_db(tweets)

if __name__ == "__main__":
    main()