import feedparser

linuxsec_ubuntu_rss = "https://linuxsecurity.com/advisories/ubuntu?format=feed&type=rss"
ubuntu_rss = "https://ubuntu.com/security/notices/rss.xml"
debian_rss = "https://www.debian.org/security/dsa"
microsoft_rss = "https://api.msrc.microsoft.com/update-guide/rss"
red_hat = "https://access.redhat.com/security/data/meta/v1/rhsa.rss"
spring = "https://spring.io/security.atom"
rss = feedparser.parse(spring)

for entry in rss.entries:
    print(entry)
    print("------")