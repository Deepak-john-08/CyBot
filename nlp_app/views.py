from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib import messages
import json
import re
# Lazy import heavy libraries only when needed
# from transformers import AutoModelForCausalLM, AutoTokenizer
# import torch
from dotenv import load_dotenv
import os
import requests
from django.views.decorators.http import require_POST
import PyPDF2
from .ml_models import predict_email_phishing, predict_url_phishing, load_models

load_dotenv()  # This will load variables from .env into os.environ

# Load ML models at startup (with error handling)
try:
    load_models()
    print("ML models loaded successfully at startup")
except Exception as e:
    print(f"Warning: Could not load ML models at startup: {e}")

# --- Improved Phishing detection stubs ---
def detect_phishing_email(email_text):
    # Enhanced rule-based phishing detection for emails
    phishing_keywords = [
        "urgent", "verify your account", "login to your account", "update your information", "suspended",
        "confirm your identity", "click the link below", "act now", "immediate action required", "reset your password",
        "security alert", "unusual activity", "account locked", "provide your credentials", "bank account",
        "transfer", "payment", "wire", "vendor", "confidential", "meeting right now", "reply when complete"
    ]
    suspicious_phrases = [
        "dear customer", "dear user", "dear valued customer", "greetings from", "official notice",
        "i need you to", "this is urgent", "urgent and confidential"
    ]
    suspicious_senders = [
        "noreply@", "support@", "admin@", "service@", "security@", "ceo@", "-security.com"
    ]
    # Financial/Business Email Compromise indicators
    bec_indicators = [
        "transfer money", "wire transfer", "new vendor", "payment request", "invoice", 
        "bank details", "account details", "routing number", "swift code"
    ]
    
    score = 0
    email_lower = email_text.lower()
    
    # Check phishing keywords
    for keyword in phishing_keywords:
        if keyword in email_lower:
            score += 2
    
    # Check suspicious phrases
    for phrase in suspicious_phrases:
        if phrase in email_lower:
            score += 2  # Increased from 1 to 2
    
    # Check suspicious senders
    for sender in suspicious_senders:
        if sender in email_lower:
            score += 2  # Increased from 1 to 2
    
    # Check BEC indicators (Business Email Compromise)
    for indicator in bec_indicators:
        if indicator in email_lower:
            score += 3  # High score for financial requests
    
    # Check for urgency + money combination (major red flag)
    if ("urgent" in email_lower or "immediately" in email_lower) and any(money_word in email_lower for money_word in ["money", "payment", "transfer", "$", "dollar"]):
        score += 4
    
    # Check for CEO/executive impersonation
    if any(exec_word in email_lower for exec_word in ["ceo", "president", "director", "manager"]) and any(request_word in email_lower for request_word in ["need you", "require", "transfer", "payment"]):
        score += 3
    
    if score >= 2:
        return True, "🚨 Whoa, hold up! This email is throwing up some serious red flags. Looks like someone's trying to pull a fast one on you—classic phishing move!"
    else:
        return False, "✅ This email looks totally legit! Clean sender, personalized message, and no sketchy stuff in sight. You're good to go!"

def detect_phishing_link(link):
    # Enhanced rule-based phishing detection for links
    suspicious_patterns = [
        # URL shorteners
        r"bit\.ly", r"tinyurl", r"t\.co", r"goo\.gl", r"ow\.ly", r"is\.gd",
        
        # IP addresses in URLs
        r"\d{1,3}(?:\.\d{1,3}){3}",
        
        # Suspicious domain patterns
        r"account-.*\.com", r".*-account\.com", r"verify-.*\.com", r".*-verify\.com",
        r"update-.*\.com", r".*-update\.com", r"secure-.*\.com", r".*-secure\.com",
        r"login-.*\.com", r".*-login\.com", r"bank-.*\.com", r".*-bank\.com",
        
        # Brand spoofing patterns
        r"paypal-.*\.com", r".*-paypal\.com", r"amazon-.*\.com", r".*-amazon\.com",
        r"google-.*\.com", r".*-google\.com", r"microsoft-.*\.com", r".*-microsoft\.com",
        
        # Suspicious TLDs
        r"[a-zA-Z0-9]+\.(ru|cn|tk|ml|ga|cf|gq|xyz|top|click|download)",
        
        # URL redirects (major red flag)
        r"redirect\?url=", r"url=http", r"link=http", r"goto=http",
        
        # Suspicious subdomains
        r"[a-zA-Z0-9-]+\.verify-user\.com", r"[a-zA-Z0-9-]+\.account-update\.com"
    ]
    
    misspelled_brands = [
        "paypa1", "faceb00k", "g00gle", "micros0ft", "amaz0n", "app1e", "gooogle", "amazom", "payp4l"
    ]
    
    # Check for obvious phishing indicators
    phishing_indicators = [
        "evil.com", "malicious", "phishing", "scam", "fake", "fraud"
    ]
    
    score = 0
    
    # Check for URL redirects (highest priority)
    if re.search(r"redirect\?url=|url=http|link=http|goto=http", link.lower()):
        score += 5
    
    # Check for obvious phishing domains
    for indicator in phishing_indicators:
        if indicator in link.lower():
            score += 5
    
    # Check suspicious patterns
    for pattern in suspicious_patterns:
        if re.search(pattern, link.lower()):
            score += 2
            break  # Don't double count
    
    # Check misspelled brands
    for brand in misspelled_brands:
        if brand in link.lower():
            score += 3
    
    # Check for suspicious domain structure
    if ".com." in link and not link.endswith(".com"):
        score += 4
    
    # Simple response based on score
    if score >= 3:
        return True, "🚨 Yikes! This link is screaming danger—definitely looks like a phishing trap designed to steal your info. I'd stay far away from this one!"
    else:
        return False, "✅ This link checks out perfectly! Clean, legitimate, and totally safe to click. Go ahead!"

# Remove DialoGPT and langchain fallback, add Ollama TinyLlama fallback

GROQ_API_KEY = os.getenv("GROQ_API_KEY")  # Store your key in .env

def groq_response(user_message, model_name="llama3-70b-8192"):
    if not GROQ_API_KEY:
        return "Groq API key not configured. Please check your .env file."
    
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": model_name,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity expert assistant. Always answer the user's specific question directly and concisely. "
                    "If the user asks for a definition, provide a clear and accurate definition of the exact term they mention, not a general topic."
                )
            },
            {"role": "user", "content": user_message}
        ]
    }
    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)  # Reduced timeout
        response.raise_for_status()
        result = response.json()
        return result["choices"][0]["message"]["content"]
    except requests.exceptions.Timeout:
        return "Response timeout. Please try again with a shorter question."
    except Exception as e:
        return f"Sorry, I'm having trouble connecting right now. Please try again later."

def rule_based_response(user_message):
    rules = [
        (r'spoofing', "Spoofing is a cyberattack where someone pretends to be a trusted source to gain access to sensitive information."),
        (r'sniffing', "Sniffing is the act of monitoring and capturing data packets passing through a network, often used to steal information."),
        (r'phishing', "Phishing is a scam where attackers trick you into giving up sensitive information by pretending to be a trustworthy entity."),
        (r'social engineering', "Social engineering is manipulating people into giving up confidential information, often by pretending to be someone trustworthy."),
        (r'malware', "Malware is malicious software designed to harm, exploit, or otherwise compromise a computer system."),
        (r'ransomware', "Ransomware is a type of malware that locks or encrypts your files and demands payment for their release."),
        (r'firewall', "A firewall is a security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules."),
        (r'virus', "A computer virus is a type of malware that attaches itself to a program or file and can spread from one computer to another."),
        (r'trojan', "A trojan is a type of malware disguised as legitimate software, used by cybercriminals to gain access to users' systems."),
        (r'botnet', "A botnet is a network of infected computers controlled by a hacker to perform tasks like sending spam or launching attacks."),
        (r'zero[- ]day', "A zero-day is a vulnerability in software that is unknown to the vendor and has not been patched, making it a target for attacks."),
        (r'brute[- ]force', "A brute-force attack is when an attacker tries many passwords or keys with the hope of eventually guessing correctly."),
        (r'encryption', "Encryption is the process of converting information into a code to prevent unauthorized access."),
        (r'2fa|two[- ]factor|multi[- ]factor', "Two-factor authentication (2FA) adds an extra layer of security by requiring two forms of identification to access an account."),
        (r'vpn', "A VPN (Virtual Private Network) encrypts your internet connection and hides your IP address for privacy and security."),
        (r'patch', "A patch is a software update that fixes security vulnerabilities and other bugs."),
        (r'update', "Always keep your software and antivirus updated to protect against threats."),
        (r'(how|steps?|tips?) (to|for)? (create|make|choose|set) (a )?strong password',
         "Here are steps to create a strong password:\n"
         "1. Use at least 12 characters (the longer, the better).\n"
         "2. Mix uppercase, lowercase, numbers, and symbols.\n"
         "3. Avoid common words, names, or easily guessed info.\n"
         "4. Don’t reuse passwords across sites.\n"
         "5. Consider using a passphrase or a password manager."),
        (r'what is (a )?strong password',
         "A strong password is long (at least 12 characters), uses a mix of letters, numbers, and symbols, and avoids common words or patterns."),
        (r'strong password',
         "A strong password should be at least 12 characters, include uppercase and lowercase letters, numbers, and symbols, and not use common words or personal info."),
        (r'password',
         "Never share your password with anyone. Use strong, unique passwords for each account."),
        (r'cybersecurity', "Cybersecurity is the practice of protecting systems, networks, and programs from digital attacks."),
        (r'firewall', "A firewall is a network security device that monitors and filters incoming and outgoing network traffic."),
        (r'backdoor', "A backdoor is a method of bypassing normal authentication to gain access to a system, often left by malware."),
        (r'spyware', "Spyware is software that secretly monitors and collects user information without their knowledge."),
        (r'adware', "Adware is software that automatically displays or downloads advertising material when a user is online."),
        (r'rootkit', "A rootkit is a collection of software tools that enable unauthorized access to a computer or network."),
        (r'ddos', "A DDoS (Distributed Denial of Service) attack overwhelms a system with traffic to make it unavailable to users."),
        (r'authentication', "Authentication is the process of verifying the identity of a user or device."),
        (r'authorization', "Authorization is the process of giving someone permission to do or have something."),
        (r'breach', "A breach is an incident where information is stolen or taken from a system without the knowledge or authorization of the system's owner."),
        (r'cookie', "A cookie is a small piece of data stored on the user's computer by the web browser while browsing a website."),
        (r'certificate', "A digital certificate is an electronic document used to prove the ownership of a public key."),
        (r'public key', "A public key is used in cryptography to encrypt messages that only the holder of the paired private key can decrypt."),
        (r'private key', "A private key is a secret key used in cryptography to decrypt messages encrypted with the paired public key."),
    ]
    for pattern, response in rules:
        if re.search(pattern, user_message, re.IGNORECASE):
            return response
    return None

# Ollama fallback for local models (Mistral or Llama2)
def ollama_response(user_message, model_name="llama2"):
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": model_name,
                "prompt": user_message,
                "stream": False
            },
            timeout=60
        )
        response.raise_for_status()
        data = response.json()
        return data.get("response", f"Sorry, I couldn't generate a response with {model_name}.")
    except Exception as e:
        return f"Error contacting Ollama ({model_name}): {e}"

@csrf_exempt
def chatbot_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_message = data.get('message', '')  # Do not lowercase
        except Exception:
            return JsonResponse({'error': 'Invalid input.'}, status=400)

        # Rule-based logic (expanded)
        rule_response = rule_based_response(user_message)
        if rule_response:
            return JsonResponse({'response': rule_response})

        # ML-First phishing detection using your trained models
        if (
            'subject:' in user_message and 'from:' in user_message and 'to:' in user_message
        ) or (
            'dear customer' in user_message or 'dear user' in user_message
        ) or any(keyword in user_message.lower() for keyword in ['email', 'from:', 'to:', 'subject:']):
            # Email phishing detection - ML model first
            ml_is_phishing, ml_confidence = predict_email_phishing(user_message)
            
            if ml_is_phishing is not None:
                if ml_is_phishing:
                    result = "🚨 Whoa, hold up! This email is throwing up some serious red flags. Looks like someone's trying to pull a fast one on you—classic phishing move!"
                else:
                    result = "✅ This email looks totally legit! Clean sender, personalized message, and no sketchy stuff in sight. You're good to go!"
            else:
                # Fallback to rule-based if ML fails
                rule_is_phishing, rule_result = detect_phishing_email(user_message)
                result = rule_result
            
            return JsonResponse({'response': result, 'phishing': ml_is_phishing if ml_is_phishing is not None else False})
            
        elif 'http' in user_message or 'www.' in user_message or any(tld in user_message.lower() for tld in ['.com', '.org', '.net', '.edu', '.gov']):
            # URL phishing detection - ML model first
            # Extract URLs from the message
            urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', user_message)
            if not urls:
                urls = re.findall(r'www\.(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', user_message)
            if not urls:
                # Extract domain-like patterns
                urls = re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?', user_message)
            
            if urls:
                url = urls[0]  # Check the first URL found
                ml_is_phishing, ml_confidence = predict_url_phishing(url)
                
                if ml_is_phishing is not None:
                    if ml_is_phishing:
                        result = "🚨 Yikes! This link is screaming danger—definitely looks like a phishing trap designed to steal your info. I'd stay far away from this one!"
                    else:
                        result = "✅ This link checks out perfectly! Clean, legitimate, and totally safe to click. Go ahead!"
                else:
                    # Fallback to rule-based if ML fails
                    rule_is_phishing, rule_result = detect_phishing_link(url)
                    result = rule_result
                
                return JsonResponse({'response': result, 'phishing': ml_is_phishing if ml_is_phishing is not None else False})
            else:
                return JsonResponse({'response': "❓ **NO URL DETECTED** - Please provide a valid URL for analysis.", 'phishing': False})

        # Groq fallback (Llama 3 70B as default)
        groq_api_response = groq_response(user_message, model_name="llama3-70b-8192")
        return JsonResponse({'response': groq_api_response})
    else:
        return JsonResponse({'error': 'POST request required.'}, status=405)

@csrf_exempt
@require_POST
def upload_pdf_view(request):
    if 'pdf' not in request.FILES:
        return JsonResponse({'error': 'No PDF uploaded.'}, status=400)
    pdf_file = request.FILES['pdf']
    try:
        reader = PyPDF2.PdfReader(pdf_file)
        text = ""
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
        # Extract questions (lines ending with ?)
        questions = re.findall(r'([^\n?]+\?)', text)
        questions = [q.strip() for q in questions if q.strip().endswith('?')]
        # For each question, get answer from CyBot (Groq)
        answers = []
        for q in questions:
            answer = groq_response(q, model_name="llama3-70b-8192")
            answers.append({'question': q, 'answer': answer})
        return JsonResponse({'qa_pairs': answers})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        
        # Validation
        if not username or not email or not password:
            return render(request, 'nlp_app/register.html', {
                'error_message': 'All fields are required.'
            })
        
        if password != confirm_password:
            return render(request, 'nlp_app/register.html', {
                'error_message': 'Passwords do not match.'
            })
        
        if len(password) < 6:
            return render(request, 'nlp_app/register.html', {
                'error_message': 'Password must be at least 6 characters long.'
            })
        
        # Check if username already exists
        if User.objects.filter(username=username).exists():
            return render(request, 'nlp_app/register.html', {
                'error_message': 'Username already exists. Please choose a different one.'
            })
        
        # Check if email already exists
        if User.objects.filter(email=email).exists():
            return render(request, 'nlp_app/register.html', {
                'error_message': 'Email already registered. Please use a different email.'
            })
        
        try:
            # Create new user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )
            
            # Log the user in automatically
            login(request, user)
            messages.success(request, 'Account created successfully! Welcome to CyBot.')
            return redirect('chatbot_page')
            
        except Exception as e:
            return render(request, 'nlp_app/register.html', {
                'error_message': 'An error occurred while creating your account. Please try again.'
            })
    
    return render(request, 'nlp_app/register.html')

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('chatbot_page')
        else:
            return render(request, 'nlp_app/login.html', {
                'error_message': 'Invalid username or password. Please try again.'
            })
    
    return render(request, 'nlp_app/login.html')

def logout_view(request):
    logout(request)
    return redirect('login')

def chatbot_page(request):
    return render(request, 'nlp_app/chatbot.html')
