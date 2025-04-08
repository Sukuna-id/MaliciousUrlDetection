# train_model.py

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from lightgbm import LGBMClassifier
import pickle
import re
from urllib.parse import urlparse
from tld import get_tld

# All Feature Engineering Functions
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        return 1
    else:
        return 0

def count_dot(url):
    return url.count('.')

def count_www(url):
    return url.count('www')

def count_atrate(url):
    return url.count('@')

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0

def count_https(url):
    return url.count('https')

def count_http(url):
    return url.count('http')

def count_per(url):
    return url.count('%')

def count_ques(url):
    return url.count('?')

def count_hyphen(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def url_length(url):
    return len(str(url))

def hostname_length(url):
    return len(urlparse(url).netloc)

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0

def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

# Load and prepare the data
print("Loading dataset...")
df = pd.read_csv('malicious_phish.csv')

# Feature Engineering
print("Performing feature engineering...")
df['use_of_ip'] = df['url'].apply(lambda i: having_ip_address(i))
df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))
df['count.'] = df['url'].apply(lambda i: count_dot(i))
df['count-www'] = df['url'].apply(lambda i: count_www(i))
df['count@'] = df['url'].apply(lambda i: count_atrate(i))
df['count_dir'] = df['url'].apply(lambda i: no_of_dir(i))
df['count_embed_domian'] = df['url'].apply(lambda i: no_of_embed(i))
df['short_url'] = df['url'].apply(lambda i: shortening_service(i))
df['count-https'] = df['url'].apply(lambda i: count_https(i))
df['count-http'] = df['url'].apply(lambda i: count_http(i))
df['count%'] = df['url'].apply(lambda i: count_per(i))
df['count?'] = df['url'].apply(lambda i: count_ques(i))
df['count-'] = df['url'].apply(lambda i: count_hyphen(i))
df['count='] = df['url'].apply(lambda i: count_equal(i))
df['url_length'] = df['url'].apply(lambda i: url_length(i))
df['hostname_length'] = df['url'].apply(lambda i: hostname_length(i))
df['sus_url'] = df['url'].apply(lambda i: suspicious_words(i))
df['fd_length'] = df['url'].apply(lambda i: fd_length(i))
df['tld'] = df['url'].apply(lambda i: get_tld(i,fail_silently=True))
df['tld_length'] = df['tld'].apply(lambda i: tld_length(i))
df['count-digits'] = df['url'].apply(lambda i: digit_count(i))
df['count-letters'] = df['url'].apply(lambda i: letter_count(i))

# Drop the 'tld' column as it's not needed for modeling
df = df.drop("tld", axis=1)

# Create label encoder for the target variable
from sklearn.preprocessing import LabelEncoder
lb_make = LabelEncoder()
df["type_code"] = lb_make.fit_transform(df["type"])

# Create features and target
print("Preparing features and target...")
X = df[['use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@',
        'count_dir', 'count_embed_domian', 'short_url', 'count-https',
        'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length',
        'hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count-digits',
        'count-letters']]

y = df['type_code']

# Split the data
print("Splitting data into train and test sets...")
X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, 
                                                    shuffle=True, random_state=5)

# Train the model
print("Training the model...")
lgb = LGBMClassifier(objective='multiclass',
                     boosting_type='gbdt',
                     n_jobs=5,
                     silent=True, 
                     random_state=5)

lgb.fit(X_train, y_train)

# Save the trained model
print("Saving the model...")
with open('url_detector_model.pkl', 'wb') as file:
    pickle.dump(lgb, file)

# Save the label encoder as well (we'll need this for predictions)
with open('label_encoder.pkl', 'wb') as file:
    pickle.dump(lb_make, file)

print("Evaluating model performance...")
from sklearn.metrics import classification_report
y_pred = lgb.predict(X_test)
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['benign', 'defacement', 'phishing', 'malware']))

print("\nAll done! Model and label encoder have been saved successfully!")

# Optional: Test the saved model
print("\nTesting saved model...")
with open('url_detector_model.pkl', 'rb') as file:
    loaded_model = pickle.load(file)
    
test_pred = loaded_model.predict(X_test[:1])
print(f"Test prediction successful: {test_pred}")