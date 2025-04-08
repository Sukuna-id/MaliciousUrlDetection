# # app.py
# from flask import Flask, request, render_template, jsonify
# import pandas as pd
# import numpy as np
# from urllib.parse import urlparse
# from tld import get_tld
# import re
# import pickle
# import os

# app = Flask(__name__)

# # Load the model
# def load_model():
#     with open('url_detector_model.pkl', 'rb') as file:
#         model = pickle.load(file)
#     return model

# # Feature extraction functions (copied from your original code)
# def having_ip_address(url):
#     match = re.search(
#         '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
#         '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
#         '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/))'
#         '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
#     return 1 if match else 0

# def abnormal_url(url):
#     hostname = urlparse(url).hostname
#     hostname = str(hostname)
#     match = re.search(hostname, url)
#     return 1 if match else 0

# # Add all other feature extraction functions here...
# # (count_dot, count_www, count_atrate, etc.)

# def get_features(url):
#     features = []
    
#     # Extract all features as per your original code
#     features.append(having_ip_address(url))
#     features.append(abnormal_url(url))
#     # Add all other feature extractions...
    
#     return np.array(features).reshape(1, -1)

# @app.route('/')
# def home():
#     return render_template('index.html')

# @app.route('/predict', methods=['POST'])
# def predict():
#     try:
#         url = request.form['url']
#         if not url:
#             return jsonify({'error': 'Please enter a URL'})
        
#         # Get features and make prediction
#         features = get_features(url)
#         model = load_model()
#         prediction = model.predict(features)[0]
        
#         # Convert prediction to result
#         result_map = {
#             0: "SAFE",
#             1: "DEFACEMENT",
#             2: "PHISHING",
#             3: "MALWARE"
#         }
#         result = result_map.get(prediction, "UNKNOWN")
        
#         return jsonify({
#             'url': url,
#             'result': result,
#             'status': 'success'
#         })
#     except Exception as e:
#         return jsonify({'error': str(e)})

# if __name__ == '__main__':
#     app.run(debug=True)
from flask import Flask, request, render_template, jsonify
import pandas as pd
import numpy as np
from urllib.parse import urlparse
from tld import get_tld
import re
import pickle
import os

app = Flask(__name__)

# Load the model and label encoder
def load_model():
    with open('url_detector_model.pkl', 'rb') as file:
        model = pickle.load(file)
    with open('label_encoder.pkl', 'rb') as file:
        label_encoder = pickle.load(file)
    return model, label_encoder

# Feature extraction functions
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    return 1 if match else 0

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    return 1 if match else 0

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
    return 1 if match else 0

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
    return 1 if match else 0

def digit_count(url):
    return sum(c.isdigit() for c in url)

def letter_count(url):
    return sum(c.isalpha() for c in url)

def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def tld_length(url):
    try:
        tld = get_tld(url, fail_silently=True)
        return len(tld) if tld else -1
    except:
        return -1

def get_features(url):
    features = []
    
    # Extract all features in the same order as training
    features.append(having_ip_address(url))
    features.append(abnormal_url(url))
    features.append(count_dot(url))
    features.append(count_www(url))
    features.append(count_atrate(url))
    features.append(no_of_dir(url))
    features.append(no_of_embed(url))
    features.append(shortening_service(url))
    features.append(count_https(url))
    features.append(count_http(url))
    features.append(count_per(url))
    features.append(count_ques(url))
    features.append(count_hyphen(url))
    features.append(count_equal(url))
    features.append(url_length(url))
    features.append(hostname_length(url))
    features.append(suspicious_words(url))
    features.append(fd_length(url))
    features.append(tld_length(url))
    features.append(digit_count(url))
    features.append(letter_count(url))
    
    return np.array(features).reshape(1, -1)

@app.route('/', methods=['GET', 'POST'])
def home():
    prediction = None
    url = None
    error = None
    
    if request.method == 'POST':
        try:
            url = request.form['url']
            if url:
                # Get features and make prediction
                features = get_features(url)
                model, label_encoder = load_model()
                prediction = model.predict(features)[0]
                prediction = label_encoder.inverse_transform([prediction])[0]
        except Exception as e:
            error = f"Error processing URL: {str(e)}"
    
    return render_template('index.html', prediction=prediction, url=url, error=error)

if __name__ == '__main__':
    app.run(debug=True)