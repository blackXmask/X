"""
Target URL configuration for dataset generation
"""

# Default targets for synthetic data generation
DEFAULT_TARGETS = [
    
  "https://example.com",
  "https://httpbin.org/get",
  "https://jsonplaceholder.typicode.com/posts/1",
  "https://reqres.in/api/users",
  "https://api.github.com",
  "https://www.google.com",
  "https://www.youtube.com",
  "https://www.facebook.com",
  "https://www.amazon.com",
  "https://www.wikipedia.org",
  "https://www.reddit.com",
  "https://www.linkedin.com",
  "https://www.microsoft.com",
  "https://www.apple.com",
  "https://www.netflix.com",
  "https://www.instagram.com",
  "https://www.github.com",
  "https://www.stackoverflow.com",
  "https://www.nytimes.com",
  "https://www.bbc.co.uk",
  "https://www.cnn.com",
  "https://www.reuters.com",
  "https://www.forbes.com",
  "https://www.bloomberg.com",
  "https://www.weather.com",
  "https://www.nasa.gov",
  "https://www.whitehouse.gov",
  "https://www.harvard.edu",
  "https://www.stanford.edu",
  "https://www.mit.edu",
  "http://testphp.vulnweb.com",
  "http://testasp.vulnweb.com",
  "http://testaspnet.vulnweb.com",
  "http://testhtml5.vulnweb.com",
  "http://www.itsecgames.com",
  "https://google-gruyere.appspot.com",
  "https://juice-shop.herokuapp.com",
  "http://zero.webappsecurity.com",
  "http://bodgeit.herokuapp.com",
  "http://dvwa.local",
  "http://mutillidae.local"
    
]

def load_targets_from_file(filepath="data/target_urls.txt"):
    """Load target URLs from file, fallback to defaults"""
    try:
        with open(filepath, 'r') as f:
            targets = [line.strip() for line in f 
                      if line.strip() and not line.startswith('#')]
        return targets if targets else DEFAULT_TARGETS
    except FileNotFoundError:
        return DEFAULT_TARGETS

def get_random_target():
    """Get random target from loaded list"""
    import random
    return random.choice(load_targets_from_file())