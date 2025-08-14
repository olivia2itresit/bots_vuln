import feedparser

linuxsec_ubuntu_rss = "https://linuxsecurity.com/advisories/ubuntu?format=feed&type=rss"
ubuntu_rss = "https://ubuntu.com/security/notices/rss.xml"
debian_rss = "https://www.debian.org/security/dsa"
microsoft_rss = "https://api.msrc.microsoft.com/update-guide/rss"
rss = feedparser.parse(microsoft_rss)

for entry in rss.entries:
    print(f"Title: {entry.title},  \nLink: {entry.link} \nDesc: {entry.description}")
    print("------")